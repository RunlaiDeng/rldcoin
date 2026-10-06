"""Unallocated-only V12/V8 derivative with mandatory ordinary-delivery gate."""
from pathlib import Path
PROJECT=Path('/Users/galaxy/GitHub/rldcoin');BASE=PROJECT/'tmp/default-relay-20260930'
OLD_HELPER=BASE/'observe-bft-four-cli-service-first-service-diag-v20-20261006.py'
OLD_CONTROLLER=BASE/'check-bft-four-cli-service-first-service-diag-v20-20261006.py'
NEW_HELPER=BASE/'observe-bft-four-cli-service-first-service-diag-v21-20261006.py'
NEW_CONTROLLER=BASE/'check-bft-four-cli-service-first-service-diag-v21-20261006.py'
DECISION='regional-bft-four-cli-unserved-promotion-v21-decision-unarmed-20261006.json'
GUARD="from bft_unserved_delivery_precondition_v1_20261006 import require_current_delivery\nrequire_current_delivery()\n"
def helper_transformations():
 return [('from bft_unserved_delivery_precondition_v1_20261006 import require_current_delivery\nrequire_current_delivery()', 'from bft_unserved_delivery_precondition_v2_20261006 import require_ready_native_scope\nrequire_ready_native_scope()'),('bft_four_cli_first_service_diagnostic_v5_20261006','bft_four_cli_first_service_diagnostic_v6_20261006'),('native-bft-four-cli-service-first-service-diag-v20-private-20261006','native-bft-four-cli-service-first-service-diag-v21-private-20261006')]
def controller_transformations(decision=DECISION):
 return [('from bft_unserved_delivery_precondition_v1_20261006 import require_current_delivery\nrequire_current_delivery()', 'from bft_unserved_delivery_precondition_v2_20261006 import require_ready_native_scope\nrequire_ready_native_scope()'),('service-first-service-diag-v20','service-first-service-diag-v21'),('regional-bft-four-cli-unserved-promotion-decision-unarmed-20261006.json',decision),('bind_bft_four_cli_unserved_promotion_20261006','bind_bft_four_cli_unserved_promotion_v21_20261006'),('regional-bft-unserved-promotion-entry-start-allocated-v20-20261006.json','regional-bft-unserved-promotion-entry-start-allocated-v21-20261006.json')]
def transform(text,changes):
 for before,after in changes:
  if before not in text:raise ValueError('missing exact unserved-priority binding')
  text=text.replace(before,after)
 return text
def helper_source():return transform(OLD_HELPER.read_text(),helper_transformations())
def controller_source(decision=DECISION):
 if decision not in (DECISION,'regional-bft-four-cli-unserved-promotion-v21-decision-allocated-20261006.json'):raise ValueError('unknown V21 decision variant')
 return transform(OLD_CONTROLLER.read_text(),controller_transformations(decision))
def validate(helper,controller,decision=DECISION):
 if helper!=helper_source() or controller!=controller_source(decision):raise ValueError('unreviewed unserved-priority helper/controller')
 compile(helper,str(NEW_HELPER),'exec');compile(controller,str(NEW_CONTROLLER),'exec');return True
