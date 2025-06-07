# Servicios/cloudtrail_functions.py

import json
from datetime import datetime, timedelta
from Servicios.utils import create_aws_client, get_db_connection

IMPORTANT_EC2_EVENTS = {
    "StartInstances", "StopInstances", "RebootInstances", "TerminateInstances", "ModifyInstanceAttribute",
    "CreateTags", "DeleteTags", "RunInstances", "AttachVolume", "DetachVolume", "ModifyVolume",
    "AssociateAddress", "DisassociateAddress", "AssignPrivateIpAddresses", "UnassignPrivateIpAddresses",
    "ModifyInstanceCreditSpecification", "ModifyInstancePlacement", "ModifyInstanceMetadataOptions", "ModifyInstanceCapacityReservationAttributes"
}


def extract_instance_id(event):
    get = lambda *paths: next(
        (p for path in paths for p in [path] if p and isinstance(p, str) and p.startswith("i-")),
        "unknown"
    )

    req = event.get("requestParameters", {})
    res = event.get("responseElements", {})

    return get(
        req.get("instanceId"),
        req.get("resourcesSet", {}).get("items", [{}])[0].get("resourceId"),
        req.get("instancesSet", {}).get("items", [{}])[0].get("instanceId"),
        res.get("instanceId"),
        res.get("instancesSet", {}).get("items", [{}])[0].get("instanceId"),
        res.get("instances", [{}])[0].get("instanceId"),
    )


def extract_changes(event):
    request = event.get("requestParameters", {})
    response = event.get("responseElements", {})

    candidates = [
        request.get("tagSet", {}).get("items"),
        response.get("tagSet", {}).get("items"),
        request.get("instances", [{}])[0].get("tagSet", {}).get("items"),
        response.get("instances", [{}])[0].get("tagSet", {}).get("items"),

        request.get("volumeId"),
        response.get("volumeId"),
        request.get("blockDeviceMapping"),
        response.get("blockDeviceMapping"),

        request.get("instanceType"),
        response.get("instanceType"),

        request.get("instanceState"),
        response.get("instanceState"),
        response.get("currentState"),
        response.get("previousState"),
        response.get("instancesSet", {}).get("items", [{}])[0].get("currentState"),
        response.get("instancesSet", {}).get("items", [{}])[0].get("previousState"),

        request.get("instances", [{}])[0].get("instanceType"),
        request.get("instances", [{}])[0].get("blockDeviceMapping"),
        request.get("instances", [{}])[0].get("imageId"),
        response.get("instances", [{}])[0].get("instanceType"),
        response.get("instances", [{}])[0].get("blockDeviceMapping"),
        response.get("instances", [{}])[0].get("imageId"),
    ]

    for candidate in candidates:
        if candidate:
            return candidate

    return "unknown"


def get_ec2_cloudtrail_events(region, credentials):
    client = create_aws_client("cloudtrail", region, credentials)
    print('Cliente', client)
    if not client:
        return {"error": "Error al crear cliente CloudTrail", "events": []}

    start_time = datetime.utcnow() - timedelta(days=7)
    all_events, next_token = [], None

    try:
        while True:
            response = client.lookup_events(
                LookupAttributes=[{
                    "AttributeKey": "EventSource",
                    "AttributeValue": "ec2.amazonaws.com"
                }],
                StartTime=start_time,
                EndTime=datetime.utcnow(),
                **({"NextToken": next_token} if next_token else {})
            )
            all_events.extend(response.get("Events", []))
            next_token = response.get("NextToken")
            if not next_token:
                break

        parsed_events = []
        for raw_event in all_events:
            try:
                detail = json.loads(raw_event.get("CloudTrailEvent", "{}"))
                event_name = detail.get("eventName")
                if event_name not in IMPORTANT_EC2_EVENTS:
                    continue

                event_id = raw_event.get("EventId")
                event_time = raw_event.get("EventTime")

                user_identity = detail.get("userIdentity", {})
                session_issuer = user_identity.get("sessionContext", {}).get("sessionIssuer", {})
                user_name = (
                    raw_event.get("Username") or
                    user_identity.get("userName") or
                    user_identity.get("principalId") or
                    session_issuer.get("userName") or
                    "unknown"
                )

                parsed_events.append({
                    "event_id": event_id,
                    "event_time": event_time,
                    "event_name": event_name,
                    "event_source": detail.get("eventSource", "unknown"),
                    "user_name": user_name,
                    "resource_name": extract_instance_id(detail),
                    "changes": extract_changes(detail)
                })

            except Exception:
                continue

        return {"events": parsed_events}

    except Exception as e:
        return {"error": f"Error al obtener eventos: {str(e)}", "events": []}


def insert_or_update_cloudtrail_events(events, region, credentials):
    conn = get_db_connection()
    if not conn:
        return {"error": "Error al conectar a la base de datos", "inserted": 0, "processed": 0}

    start_time = datetime.utcnow() - timedelta(days=7)
    inserted, processed = 0, 0

    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id_event, event_time 
                FROM ec2_cloudtrail_events 
                WHERE event_time >= %s
            """, (start_time,))
            existing_keys = {
                f"{row[0]}_{row[1].isoformat()}" for row in cursor.fetchall()
            }

        with conn.cursor() as cursor:
            for event in events:
                processed += 1
                key = f"{event['event_id']}_{event['event_time'].isoformat()}"
                if key in existing_keys:
                    continue

                cursor.execute("""
                    INSERT INTO ec2_cloudtrail_events (
                        id_event, event_name, event_time, user_name,
                        event_source, resource_name, changes
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (
                    event["event_id"],
                    event["event_name"],
                    event["event_time"],
                    event["user_name"],
                    event["event_source"],
                    event["resource_name"],
                    json.dumps(event["changes"])
                ))
                inserted += 1

        conn.commit()
        return {"inserted": inserted, "processed": processed}

    except Exception as e:
        conn.rollback()
        return {"error": str(e), "inserted": inserted, "processed": processed}

    finally:
        conn.close()
