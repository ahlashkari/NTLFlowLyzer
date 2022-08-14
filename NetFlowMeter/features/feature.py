#!/usr/bin/env python3

from abc import ABC, abstractmethod

class Feature(ABC):
    name: str
    @abstractmethod
    def extract(self, flow: object) -> dict:
        pass

    def set_floating_point_unit(self, floating_point_unit: str) -> None:
        self.floating_point_unit = floating_point_unit
