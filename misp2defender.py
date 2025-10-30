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


def push_indicators_post(headers, push_indicator_sentinel):
    logger.info("Pushing {} indicators to Defender".format(len(push_indicator_sentinel)))
    return True
                         
def already_in_sentinel(misp_indicator):
    return False

def get_misp_events_upload_indicators():
    misp = PyMISP(config.misp_domain, config.misp_key, config.misp_verifycert, False)
    
    logger.debug("Query MISP for events")
    remaining_misp_pages = True
    indicator_count = 0
    misp_page = 1

    if config.write_parsed_indicators:
        # Clear existing parsed indicators file
        with open(PARSED_INDICATORS_FILE_NAME, "w") as fp:
            fp.write("")

    data = {
        'client_id': config.graph_auth["client_id"],
        'grant_type': 'client_credentials',
        'client_secret': config.graph_auth["client_secret"],
        'scope': config.targetScope,
        }
    try:
        access_token = requests.post("https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(config.graph_auth["tenant"]), data=data)
        if "access_token" in access_token.json():
            headers = {"Authorization": "Bearer {}".format(access_token.json()["access_token"]), "Content-Type": "application/json"}
            logger.info("Received access token for Microsoft Defender API")
        else:
            logger.error("No token received {}".format(access_token.text))
            sys.exit()
    except:
        logger.error("No access token received")
        sys.exit()

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

                    if config.write_parsed_eventid:
                        logger.info("Processing event {} {}".format(event["Event"]["id"], event["Event"]["info"]))

                    for element in misp_event.flatten_attributes:
                        if element["value"] not in indicator_values:
                            if element.get("to_ids", False) and \
                                        element.get("type", "") in UPLOAD_INDICATOR_MISP_ACCEPTED_TYPES:
                                misp_indicator = RequestObject_Indicator(element, misp_event, logger)

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
                                        logger.debug("Skipping indicator because valid_until is in the past: {} {}".format(misp_indicator.valid_until, element["value"]))
                                        continue
                                if misp_indicator.value != "":
                                    skip_to_sentinel = False
                                    if config.ms_check_if_exist_in_sentinel:
                                        start_time = datetime.datetime.now(datetime.timezone.utc)
                                        in_sentinel = already_in_sentinel(misp_indicator)
                                        end_time = datetime.datetime.now(datetime.timezone.utc)
                                        duration = end_time - start_time
                                        #logger.info("already_in_sentinel check duration for %s: %s", misp_indicator.pattern, str(duration))
                                        if in_sentinel:
                                            skip_to_sentinel = True
                                            logger.debug("Skipping indicator already in Sentinel: {}}".format(misp_indicator.value))
                                    if not skip_to_sentinel:
                                        if config.verbose_log:
                                            logger.debug("Add {} to list of indicators to upload".format(misp_indicator.value))
                                        indicator_get_defender = misp_indicator.get_defender()
                                        if indicator_get_defender:
                                            result_set.append(indicator_get_defender)
                                            indicator_values.append(element["value"])
                                        else:
                                            logger.error("Unable to add {} of type {} to Defender. Not mapped.".format(misp_indicator.value, misp_indicator.attr_type))
                            
                logger.info("Processed {} indicators".format(len(result_set)))
                indicator_count = indicator_count + len(result_set)
                misp_page += 1
            else:
                remaining_misp_pages = False

            if config.dry_run:
                logger.info("Dry run. Not uploading to Defender")
                if config.write_parsed_indicators:
                    write_parsed_indicators(result_set)
            else:
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

    return indicator_count

def write_parsed_indicators(parsed_indicators):
    json_formatted_str = json.dumps(parsed_indicators, indent=4)
    with open(PARSED_INDICATORS_FILE_NAME, "a") as fp:
        fp.write(json_formatted_str)

def main():
    logger.info("Fetching and parsing data from MISP {}".format(config.misp_domain))
    total_indicators = get_misp_events_upload_indicators()
    logger.info("Received {} indicators in MISP".format(total_indicators))


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




