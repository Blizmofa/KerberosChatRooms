from abc import ABC, abstractmethod


class ProtocolHandlerInterfaces(ABC):
    """Protocol Handler Interfaces Class is an auxiliary class to improve server performances."""

    @abstractmethod
    def pack_request(self, fmt: str, *args) -> bytes:
        """Main pack packet method to be override."""
        raise NotImplementedError(f"{self.pack_request.__name__} must be implemented.")

    @abstractmethod
    def unpack_request(self, request_code: int, received_packet: bytes) -> tuple:
        """Main unpack packet method to be override."""
        raise NotImplementedError(f"{self.unpack_request.__name__} must be implemented.")