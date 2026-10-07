"""Attach independent first-service diagnostics to the original four owners.

Native startup, observation, receipt, cold verification and stop stay in the
reviewed driver. This extension adds no start, key, signing or recovery path.
"""
import importlib.util
from pathlib import Path
import time
from bft_four_cli_independent_trace_journal_20261006 import FourCLI as OriginalFourCLI
from first_service_diagnostic_collector_v4_20261007 import Collector
import interstellar_mesh as mesh

BASE = Path('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930')
ENTRY = BASE/'first_service_diagnostic_entry_v33_20261007.py'
spec = importlib.util.spec_from_file_location('bound_first_service_entry', ENTRY)
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)

class FourCLI(OriginalFourCLI):
    def launch(self):
        contract = entry.load_contract()
        super().launch()
        self.first_service = Collector.attach(self,contract=contract,
                                              contract_sha256=entry.CONTRACT_SHA256,entry=ENTRY)

    def observe(self):
        heights = super().observe()
        self.first_service.collect()
        return heights

    def stop_all(self):
        try:
            if hasattr(self,'first_service'):
                self.first_service.stop_collection()
        finally:
            super().stop_all()

    def retain_final_observations(self):
        try:
            super().retain_final_observations()
        finally:
            if hasattr(self,'first_service'):
                try:
                    if time.monotonic() < self.deadline and self.first_service.error is None:
                        self.first_service.read_once(require_live=False)
                    else:
                        self.first_service.failed = True
                finally:
                    try:
                        self.first_service.close()
                    finally:
                        mesh.atomic(self.output/'first-service-journal.json',self.first_service.snapshot())
