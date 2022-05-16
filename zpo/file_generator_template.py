
import logging
import os
from typing import Callable, Dict

from zpo.file_generator import FileGenerator
from zpo.template_graph import TemplateGraph


class TemplateBasedFileGenerator(FileGenerator):

    def __init__(self, template_path, output_path):
        self.template_path: str = template_path
        self.output_path: str = output_path
        self.markers: Dict = {}

    def set_marker(self, marker, content_or_func: str or Callable[[TemplateGraph, object], str]):
        self.markers[marker] = content_or_func

    def _get_marker_content(self, marker, template_graph: TemplateGraph):
        marker_content = self.markers[marker]

        if type(marker_content) == str:
            return marker_content
        else:
            return marker_content(template_graph, self)

    def _check_markers_exist(self, content):
        for marker in self.markers:
            if marker not in content:
                raise ValueError("Marker '%s' not found in template file: %s" % (
                    marker, self.template_path))

    def _replace_markers(self, template_graph, content):
        result = content

        for marker in self.markers:
            result = result.replace(
                marker, self._get_marker_content(marker, template_graph))

        return result

    def generate(self, template_graph):
        template_content = ""
        with open(self.template_path, 'r') as file:
            template_content = file.read()

        self._check_markers_exist(template_content)

        output_content = self._replace_markers(
            template_graph, template_content)

        self.write_file(output_content)

        logging.info("Generated %s" % os.path.basename(self.output_path))
