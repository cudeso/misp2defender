import config
from constants import *
from datetime import datetime, timedelta, timezone

class RequestObject_Indicator:
    def __init__(self, element, misp_event, logger):
        self.mapping = {
            "md5": "FileMd5",
            "sha1": "FileSha1",
            "sha256": "FileSha256",
            "url": "Url",
            "domain": "DomainName",
            "hostname": "DomainName",
            "hostname|port": "DomainName",
            "ip-src": "IpAddress",
            "ip-dst": "IpAddress",
            "ip-src|port": "IpAddress",
            "ip-dst|port": "IpAddress",
        }

        self.description = "Event {} (ID: {})".format(misp_event.info, misp_event.id)
        self.valid_from = self.ts_to_iso(element.get("timestamp", None))

        def _to_datetime(value):
            if isinstance(value, datetime):
                return value
            if value is None:
                return datetime.now(timezone.utc)
            if isinstance(value, (int, float)):
                try:
                    return datetime.fromtimestamp(value, tz=timezone.utc)
                except Exception:
                    pass
            if isinstance(value, str):
                s = value.strip()
                if s.endswith('Z'):
                    s = s[:-1] + '+00:00'
                try:
                    return datetime.fromisoformat(s)
                except Exception:
                    try:
                        from dateutil import parser as _parser
                        return _parser.parse(s)
                    except Exception:
                        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                            try:
                                return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
                            except Exception:
                                continue
            return datetime.now(timezone.utc)

        days_to_expire = int(getattr(config, 'days_to_expire', 0) or 0)
        valid_from_dt = _to_datetime(self.valid_from)
        date_object = valid_from_dt + timedelta(days=days_to_expire)
        self.valid_until = date_object.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')

        self.attr_type = element.get("type", "")
        self.attr_type_mapping = self.mapping.get(self.attr_type)
        self.value = element.get("value", "").strip()
        if "|" in self.value:
            self.value = self.value.split("|")[0].strip()
        self.to_ids = element.get("to_ids", False)
        self.misp_event = misp_event

        self.threat_level = self.misp_event.threat_level
        self.defender_action = config.defender_action

        for tag in element.get("Tag", []):
            if tag.get("name", "").startswith("misp:threat-level="):
                tag_threat_level = tag.get("name", "").split("=")[1].strip().lower()
                if tag_threat_level == "high-risk":
                    self.threat_level = "High"
                elif tag_threat_level == "medium-risk":
                    self.threat_level = "Medium"
                elif tag_threat_level == "low-risk":
                    self.threat_level = "Low"
                elif tag_threat_level == "no-risk":
                    self.threat_level = "Informational"
            if tag.get("name", "").startswith("course-of-action:passive="):
                self.defender_action = "Audit"
            if tag.get("name", "").startswith("coa:detect="):
                self.defender_action = "Audit"
            if tag.get("name", "").startswith("coa:discover="):
                self.defender_action = "Audit"
            if tag.get("name", "").startswith("course-of-action:active="):
                self.defender_action = "Block"
            if tag.get("name", "").startswith("coa:deny="):
                self.defender_action = "Block"
            if tag.get("name", "").startswith("coa:degrade="):
                self.defender_action = "Block"
            if tag.get("name", "").startswith("coa:deceive="):
                self.defender_action = "Block"
            if tag.get("name", "").startswith("coa:disrupt="):
                self.defender_action = "Block"

        if config.days_to_expire_ignore_misp_last_seen or not element.get("valid_until", False):
            days_to_expire = config.days_to_expire

            # Custom mapping for TLPs
            override_expire = False
            if hasattr(config, "days_to_expire_tlpclear"):
                if len(self.misp_event.tag) > 0:
                    for tag in self.misp_event.tag:
                        days_to_expire_tlpclear_tags = ["tlp:clear", "tlp:white"]
                        for d in days_to_expire_tlpclear_tags:
                            if d.lower().strip() in tag["name"].lower().strip():
                                days_to_expire = config.days_to_expire_tlpclear
                                override_expire = True
            if override_expire:
                self.description = "{} - {}".format(self.description, "Limited expiration date due to tlp:clear")

            # If we have a mapping, then we use a custom number of days to expire
            if not override_expire and hasattr(config, "days_to_expire_mapping"):
                for el in config.days_to_expire_mapping:
                    if el.strip().lower() in self.attr_type_mapping.lower():
                        days_to_expire = config.days_to_expire_mapping[el]

            if config.days_to_expire_start.lower().strip() == "current_date":
                date_object = datetime.now() + timedelta(days=days_to_expire)
            elif config.days_to_expire_start.lower().strip() == "valid_from":
                date_object = valid_from_dt + timedelta(days=days_to_expire)
            if date_object:
                self.valid_until = self.ts_to_iso(date_object.timestamp())
            else:
                self.logger.error("Could not set valid_until for indicator {}".format(self.pattern))

    def get_defender(self):


        indicatorType = self.mapping.get(self.attr_type)

        if indicatorType:
            indicator_defender = {
                "indicatorValue": self.value,
                "indicatorType": indicatorType,
                "title": self.misp_event.info,
                "application": config.defender_application,
                "expirationTime": self.valid_until,
                "action": config.defender_action,
                "severity": self.threat_level,
                "recommendedActions": config.defender_recommended_actions,
                "generateAlert": config.defender_generate_alert,
                "description": self.description
            }
            return indicator_defender
        return False

    def ts_to_iso(self, ts: int | str | None) -> str:
        if not ts:
            return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        try:
            ts = int(ts)
        except Exception:
            return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        return datetime.utcfromtimestamp(ts).replace(microsecond=0).isoformat() + "Z"


class RequestObject_Event:
    def __init__(self, event, logger, misp_flatten_attributes=False):
        self.tag = event["Tag"]
        if misp_flatten_attributes:
            object_attributes = []
            for misp_object in event["Object"]:
                for object_attribute in misp_object["Attribute"]:
                    if len(object_attribute["comment"].strip()) > 0:
                        comment = "{} (was part of {} object)".format(object_attribute["comment"], misp_object["name"])
                    else:
                        comment = "(was part of {} object)".format(misp_object["name"])
                    object_attribute["comment"] = comment
                    object_attributes.append(object_attribute)
            event_attributes = object_attributes + event["Attribute"]
            event["Attribute"] = event_attributes
            event["Object"] = []
            self.event = event
            self.flatten_attributes = event_attributes
        else:
            self.event = event
            self.flatten_attributes = []

        self.uuid = event["uuid"]
        self.info = event["info"]
        self.id = event["id"]
        self.distribution = event["distribution"]
        if hasattr(config, "defender_severity"):
            self.threat_level = config.defender_severity
        else:
            threat_level_id = event["threat_level_id"]
            if threat_level_id == "1":
                self.threat_level = "High"
            elif threat_level_id == "2":
                self.threat_level = "Medium"
            elif threat_level_id == "3":
                self.threat_level = "Low"
            else:
                self.threat_level = "Informational"

        self.eventdate = event["date"]
        self.org = event["Orgc"]["name"].strip()
        self.org_uuid = event["Orgc"]["uuid"]
