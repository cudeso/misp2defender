import requests
import json
import sys
from pymisp import *
import datetime
import config
import time
import logging
from RequestObject import RequestObject_Event, RequestObject_Indicator
from constants import *

if config.misp_verifycert is False:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_custom_user_agent():
    """
    Returns a custom browser user agent string for Microsoft requests.
    Modify this function to customize the user agent as needed.
    """
    if hasattr(config, 'custom_user_agent') and config.custom_user_agent:
        return config.custom_user_agent
    # Default to a common browser user agent
    return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def push_indicators_post(headers, push_indicator_sentinel):
    request_body = {"Indicators": push_indicator_sentinel}
    resp = requests.post("https://api.securitycenter.microsoft.com/api/indicators/import", headers=headers, json=request_body)
    try:
        resp_json = resp.json()
        
        # Log JSON response to file if configured
        if hasattr(config, 'log_json_file') and config.log_json_file:
            with open(config.log_json_file, "a") as json_log:
                json_log.write(json.dumps(resp_json, indent=2) + "\n")
        
        if "error" in resp_json:
            logger.error(request_body)
            logger.error("Error: {}".format(resp_json["error"]))
        else:
            logger.info("Pushing {} indicators to Defender".format(len(push_indicator_sentinel)))
    except json.JSONDecodeError:
        logger.error("Invalid JSON response: {}".format(resp.text))
    return True

def get_misp_events_upload_indicators(existing_indicators):
    misp = PyMISP(config.misp_domain, config.misp_key, config.misp_verifycert, False)

    logger.debug("Query MISP for events")
    remaining_misp_pages = True
    indicator_count = 0
    ignore_in_otx = 0
    ignore_already_in_defender = 0
    misp_page = 1

    if config.write_parsed_indicators:
        # Clear existing parsed indicators file
        with open(PARSED_INDICATORS_FILE_NAME, "w") as fp:
            fp.write("")

    if not config.dry_run:
        headers = get_headers_with_access_token()
        if not headers:
            return False
    else:
        logger.info("Dry run. Not uploading to Defender")

    while remaining_misp_pages:
        result_set = []
        indicator_values = []

        try:
            if "limit" in config.misp_event_filters:
                result = misp.search(controller='events', return_format='json', **config.misp_event_filters)
                remaining_misp_pages = False # Limits are set in the misp_event_filters
            else:
                result = misp.search(controller='events', return_format='json', **config.misp_event_filters, limit=config.misp_event_limit_per_page, page=misp_page)

            if len(result) > 0:
                logger.info("Received MISP events page {} with {} events".format(misp_page, len(result)))
                
                for event in result:
                    misp_event = RequestObject_Event(event["Event"], logger, config.misp_flatten_attributes)
                    check_for_vetted = False

                    if config.write_parsed_eventid:
                        logger.info("Process event {} {} from {}".format(event["Event"]["id"], event["Event"]["info"], event["Event"]["Orgc"]["name"]))

                    event_tags_lower = [tag["name"].lower() for tag in misp_event.tag]
                    if hasattr(config, "limit_vetted_attributes_from_specific_events") and hasattr(config, "vetted_attribute_classifier"):
                        for tag in config.limit_vetted_attributes_from_specific_events:
                            if tag.lower() in event_tags_lower:
                                check_for_vetted = True
                                logger.debug("Event {} {} requires vetted attributes only".format(misp_event.id, misp_event.info))

                    for element in misp_event.flatten_attributes:
                        if element["value"] in existing_indicators:
                            logger.debug("Skip indicator because already in Defender {}".format(element["value"]))
                            ignore_already_in_defender += 1
                            continue

                        if element["value"] in indicator_values:
                            logger.debug("Skip indicator because already processed {}".format(element["value"]))
                        else:
                            if element.get("to_ids", False) and \
                                        element.get("type", "") in UPLOAD_INDICATOR_MISP_ACCEPTED_TYPES:
                                misp_indicator = RequestObject_Indicator(element, misp_event, logger)

                                skip_indicator = False

                                if check_for_vetted:
                                    attribute_tags_lower = [tag["name"].lower() for tag in element.get("Tag", [])]
                                    vetted_tags_lower = [t.lower() for t in config.vetted_attribute_classifier]
                                    is_vetted = any(tag in vetted_tags_lower for tag in attribute_tags_lower)
                                    
                                    if is_vetted:
                                        logger.debug("Attribute {} is vetted, will be uploaded".format(misp_indicator.value))
                                    else:
                                        logger.debug("Attribute {} is not vetted, will be skipped".format(misp_indicator.value))                                        
                                        skip_indicator = True

                                if hasattr(config, "exclude_if_in_alienvault"):
                                    if config.exclude_if_in_alienvault:
                                        from OTXv2 import OTXv2, IndicatorTypes
                                        otx = OTXv2(config.otx_alienvault_api)
                                        otx_indicator = {
                                            "md5": IndicatorTypes.FILE_HASH_MD5,
                                            "sha1": IndicatorTypes.FILE_HASH_SHA1,
                                            "sha256": IndicatorTypes.FILE_HASH_SHA256,
                                            "url": IndicatorTypes.URL,
                                            "ip-dst": IndicatorTypes.IPv4,
                                            "ip-src": IndicatorTypes.IPv4,
                                            "domain": IndicatorTypes.DOMAIN,
                                            "hostname": IndicatorTypes.HOSTNAME,
                                        }
                                        if element["type"] in otx_indicator:
                                            try:
                                              r = otx.get_indicator_details_full(otx_indicator[element["type"]], element["value"])
                                              if len(r) > 0:
                                                  logger.debug("Skip indicator because in OTX {}".format(element["value"]))
                                                  ignore_in_otx += 1
                                                  skip_indicator = True
                                            except Exception as e:
                                                logger.debug("Error checking OTX for {}: {}".format(element["value"], e))

                                if not skip_indicator:
                                    if misp_indicator.valid_until:
                                        try:
                                            vu_dt = datetime.datetime.strptime(misp_indicator.valid_until, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
                                        except Exception:
                                            try:
                                                vu_dt = datetime.datetime.fromisoformat(misp_indicator.valid_until.replace('Z', '+00:00'))
                                            except Exception:
                                                logger.debug("Unable to parse valid_until {}, skipping indicator {}".format(misp_indicator.valid_until, element["value"]))
                                                continue
                                        if vu_dt <= datetime.datetime.now(datetime.timezone.utc):
                                            logger.debug("Skip indicator because valid_until is in the past: {} {}".format(misp_indicator.valid_until, element["value"]))
                                            continue
                                    if misp_indicator.value != "":
                                        indicator_get_defender = misp_indicator.get_defender()
                                        if indicator_get_defender:
                                            if config.verbose_log:
                                                logger.debug("Push {} from {} {}".format(misp_indicator.value, misp_event.info, misp_event.id))
                                            result_set.append(indicator_get_defender)
                                            indicator_values.append(element["value"])
                                        else:
                                            logger.error("Unable to add {} of type {} to Defender. Not mapped.".format(misp_indicator.value, misp_indicator.attr_type))

                logger.info("Processed {} indicators".format(len(result_set)))
                indicator_count = indicator_count + len(result_set)
                misp_page += 1
            else:
                remaining_misp_pages = False

            # Write indicators
            if config.write_parsed_indicators:
                write_parsed_indicators(result_set) 

            if not config.dry_run:
                counter = 0
                while len(result_set) > 0:
                    counter += 1
                    if counter > config.quota_requests:
                        logger.info("Waiting for API ; max queries / minute (quota_requests: {}".format(config.quota_requests))
                        time.sleep(62)
                        counter = 0

                    push_indicators_post(headers, result_set[:config.max_indicators_per_query])
                    result_set = result_set[config.max_indicators_per_query:]

        except Exception as e:
            remaining_misp_pages = False
            logger.error("Error when processing data from MISP {} - {} - {}".format(e, sys.exc_info()[2].tb_lineno, sys.exc_info()[1]))

    return indicator_count, ignore_already_in_defender, ignore_in_otx

def write_parsed_indicators(parsed_indicators):
    json_formatted_str = json.dumps(parsed_indicators, indent=4)
    with open(PARSED_INDICATORS_FILE_NAME, "a") as fp:
        fp.write(json_formatted_str)

def get_headers_with_access_token():
    headers = False
    data = {
        'client_id': config.graph_auth["client_id"],
        'grant_type': 'client_credentials',
        'client_secret': config.graph_auth["client_secret"],
        'scope': config.targetScope,
        }
    try:
        access_token = requests.post("https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(config.graph_auth["tenant"]), data=data)
        if "access_token" in access_token.json():
            headers = {
                "Authorization": "Bearer {}".format(access_token.json()["access_token"]), 
                "Content-Type": "application/json",
                "User-Agent": get_custom_user_agent()
            }
            logger.info("Received access token for Microsoft Defender API")
        else:
            logger.error("No token received {}".format(access_token.text))
            sys.exit()
    except:
        logger.error("No access token received")
        sys.exit()

    return headers

def fetch_existing_indicators(existing_indicators):
    headers = get_headers_with_access_token()
    reached_query_limit_defender = False # Query limit is set by Defender to 10000
    if headers:
        response = requests.get("https://api.securitycenter.microsoft.com/api/indicators/", headers=headers)
        # Optional filtering with ?$filter=action+eq+'{}'
        if response.status_code == 200:
            if "value" in response.json():
                response_value = response.json()["value"]
                logger.info("There are {} existing indicators in Defender".format(len(response_value)))
                if len(response_value) >= 10000:
                    reached_query_limit_defender = True
                    logger.warning("Reached query limit of 10000 indicators from Defender.")   
                for entry in response_value:
                     if entry["indicatorValue"] not in existing_indicators:
                         existing_indicators.append(entry["indicatorValue"])
                logger.info("Got {} unique indicators".format(len(existing_indicators)))
        else:
            logger.error("Did not receive response from Defender while querying for indicators {} {}".format(response.status_code, response.text))

        if reached_query_limit_defender:
            response = requests.get("https://api.securitycenter.microsoft.com/api/indicators/?$skip=10000", headers=headers)
            if response.status_code == 200:
                if "value" in response.json():
                    response_value = response.json()["value"]
                    logger.info("There are {} additional existing indicators in Defender".format(len(response_value)))
                    if len(response_value) >= 10000:
                        reached_query_limit_defender = True
                        logger.warning("Reached query limit of 10000 indicators from Defender.")   
                    for entry in response_value:
                        if entry["indicatorValue"] not in existing_indicators:
                            existing_indicators.append(entry["indicatorValue"])
                    logger.info("Got {} unique indicators".format(len(existing_indicators)))
            else:
                logger.error("Did not receive response from Defender while querying for indicators {} {}".format(response.status_code, response.text))
    return existing_indicators

def main():
    existing_indicators = []
    if not config.dry_run:
        if config.check_if_already_in_defender:
            existing_indicators = fetch_existing_indicators(existing_indicators)
    logger.info("Fetching and parsing data from MISP {}".format(config.misp_domain))
    total_indicators, ignore_already_in_defender, ignore_in_otx = get_misp_events_upload_indicators(existing_indicators)
    logger.info("Pushed {} indicators from MISP. Skipped {} because already in Defender. Skipped {} because known in OTX.".format(total_indicators,ignore_already_in_defender, ignore_in_otx))


if __name__ == '__main__':
    logger = logging.getLogger("misp2defender")
    logger.setLevel(logging.INFO)
    if config.verbose_log:
        logger.setLevel(logging.DEBUG)
    ch = logging.FileHandler(config.log_file, mode="a")
    ch.setLevel(logging.INFO)
    if config.verbose_log:
        ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    logger.info("Start MISP2Defender")
    main()
    logger.info("End MISP2Defender")


