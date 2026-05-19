import logging

logger = logging.getLogger("BGP-Monitor.Exporters")

class BaseExporter:
    """Base class for all BGP event exporters."""
    def __init__(self, config):
        self.config = config

    def export_event(self, event_data):
        """
        Export a single BGP security event.
        :param event_data: Dictionary containing prefix, asn, type, etc.
        """
        raise NotImplementedError("Exporters must implement export_event")

    def export_health_check(self, health_data):
        """
        Export RPKI health audit results.
        :param health_data: Dictionary containing summary stats and timestamp.
        """
        pass # Optional implementation
