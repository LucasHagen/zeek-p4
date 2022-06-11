import logging
import os
from typing import Callable, Dict
from zpo.exceptions import ZpoException

from zpo.file_generator import FileGenerator
from zpo.exec_graph import ExecGraph


class TemplateBasedFileGenerator(FileGenerator):
    """A file generator that reads a template file and replaces all markers in
    that file by the defined content.
    """

    def __init__(self, template_path: str, output_path: str):
        """Constructor.

        Args:
            template_path (str): the path to the template file
            output_path (str): the path to the output file (will override)
        """
        self.template_path: str = template_path
        self.output_path: str = output_path
        self.markers: Dict = {}

    def add_marker(self, marker_id: str, content_or_func: str or Callable[[ExecGraph, FileGenerator], str]):
        """Adds a marker to the generator. The `content_or_func` can be either a string, or a
        function that returns a string (lazy loaded). The function is stored in this generator
        and is only called when the file is actually generated.

        The function, if used, is called passing the TemplateGraph and the generator instance.

        Args:
            marker_id (str): marker (unique) id
            content_or_func (str|Callable[[TemplateGraph, FileGenerator], str]): a string content or a
                function that receives [TemplateGraph, FileGenerator] and return a [str].

        Raises:
            ZpoException: marker already defined
        """
        if marker_id in self.markers:
            raise ZpoException(f"Marker '{marker_id}' already defined")

        self.markers[marker_id] = content_or_func

    def _get_marker_content(self, marker, template_graph: ExecGraph):
        """Returns the content (if marker is set to string) or evaluates the function set to the
        marker and returns its content.
        """
        marker_content = self.markers[marker]

        if type(marker_content) == str:
            return marker_content
        else:
            return marker_content(template_graph, self)

    def _check_markers_exist(self, content):
        """Checks if all markers exists in `content`. If one or more markers don't exist,
        `ZpoException` is raised.
        """
        for marker in self.markers:
            if marker not in content:
                raise ZpoException("Marker '%s' not found in template file: %s" % (
                    marker, self.template_path))

    def _replace_markers(self, template_graph, content):
        """Replaces all markers in `content`.

        This doesn't check if markers exist.
        """
        result = content

        for marker in self.markers:
            result = result.replace(
                marker, self._get_marker_content(marker, template_graph))

        return result

    def generate(self, template_graph: ExecGraph):
        """Generates the file.
            1. Reads the template.
            2. Replaces all defined markers.
            3. Writes the output file.

        Args:
            template_graph (TemplateGraph): the template graph
        """
        template_content = ""
        with open(self.template_path, 'r') as file:
            template_content = file.read()

        self._check_markers_exist(template_content)

        output_content = self._replace_markers(
            template_graph, template_content)

        self.write_file(output_content)

        logging.info("Generated %s" % os.path.basename(self.output_path))
