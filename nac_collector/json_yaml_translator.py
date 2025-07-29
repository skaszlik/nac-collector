"""
JSON to YAML Translator for NDFC configurations
This module provides functionality to translate JSON configuration files
into structured YAML files using mapping configuration templates.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Union

import jsonpath_ng
from ruamel.yaml import YAML

logger = logging.getLogger(__name__)


class NDFCJsonYamlTranslator:
    """
    Translates JSON configuration files to YAML format using mapping configurations.
    
    This class processes JSON data (typically from NDFC fabric settings) and converts
    it to structured YAML files based on mapping rules defined in a configuration file.
    """
    
    # List of supported fabric types for translation
    SUPPORTED_FABRIC_TYPES = [
        "VXLAN EVPN",           # Standard VXLAN EVPN fabric
        "VXLAN_EVPN",           # Alternative naming convention
    ]

    def __init__(self, map_config_file: str):
        """
        Initialize the translator with a mapping configuration file.
        
        Args:
            map_config_file (str): Path to the YAML mapping configuration file
        """
        self.map_config_file = map_config_file
        self.map_config = None
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        self.yaml.width = 4096
        self.yaml.indent(mapping=2, sequence=4, offset=2)
        
        # Load the mapping configuration
        self._load_map_config()

    def _load_map_config(self):
        """Load the mapping configuration from the YAML file."""
        try:
            with open(self.map_config_file, 'r', encoding='utf-8') as f:
                self.map_config = self.yaml.load(f)
            logger.info("Loaded mapping configuration from: %s", self.map_config_file)
        except FileNotFoundError:
            logger.error("Mapping configuration file not found: %s", self.map_config_file)
            raise
        except Exception as e:
            logger.error("Error loading mapping configuration: %s", e)
            raise

    def _extract_json_value(self, json_data: Dict[str, Any], json_path: str) -> Any:
        """
        Extract a value from JSON data using JSONPath.
        
        Args:
            json_data (Dict[str, Any]): The JSON data to search
            json_path (str): JSONPath expression (e.g., "$.fabricName")
            
        Returns:
            Any: The extracted value, or None if not found
        """
        try:
            # Parse the JSONPath expression
            jsonpath_expr = jsonpath_ng.parse(json_path)
            matches = jsonpath_expr.find(json_data)
            
            if matches:
                # Return the first match
                return matches[0].value
            else:
                logger.debug("No match found for JSONPath: %s", json_path)
                return None
                
        except Exception as e:
            logger.error("Error extracting JSON value with path '%s': %s", json_path, e)
            return None

    def _apply_transformations(self, value: Any, transformations: List[Dict[str, Any]]) -> Any:
        """
        Apply a list of transformations to a value.
        
        Args:
            value (Any): The input value to transform
            transformations (List[Dict[str, Any]]): List of transformation configurations
            
        Returns:
            Any: The transformed value
        """
        if not transformations:
            return value
            
        for transformation in transformations:
            trans_type = transformation.get('type')
            
            if trans_type == 'replace_string':
                if isinstance(value, str):
                    from_str = transformation.get('from', '')
                    to_str = transformation.get('to', '')
                    value = value.replace(from_str, to_str)
                    
            elif trans_type == 'to_lowercase':
                if isinstance(value, str):
                    value = value.lower()
                    
            elif trans_type == 'map_value':
                mapping = transformation.get('mapping', {})
                default = transformation.get('default', '{{ value }}')
                
                if str(value) in mapping:
                    value = mapping[str(value)]
                else:
                    # Handle default value with template substitution
                    if default == '{{ value }}':
                        # Keep original value
                        pass
                    else:
                        value = default
                        
            elif trans_type == 'to_integer':
                try:
                    value = int(value)
                except (ValueError, TypeError):
                    logger.warning("Could not convert value to integer: %s", value)
                    
            elif trans_type == 'to_boolean':
                if isinstance(value, str):
                    # Convert string representations to boolean
                    lower_value = value.lower().strip().strip("'").strip('"')
                    if lower_value in ('true', '1', 'yes', 'on', 'enabled'):
                        value = True
                    elif lower_value in ('false', '0', 'no', 'off', 'disabled'):
                        value = False
                    else:
                        logger.warning("Could not convert string value '%s' to boolean", value)
                elif isinstance(value, (int, float)):
                    # Convert numeric values to boolean
                    value = bool(value)
                elif isinstance(value, bool):
                    # Already a boolean, keep as is
                    pass
                else:
                    logger.warning("Could not convert value of type %s to boolean: %s", type(value).__name__, value)
                    
            elif trans_type == 'split_range':
                if isinstance(value, str) and '-' in value:
                    try:
                        # Split the range string (e.g., "20010-29999" -> {"from": 20010, "to": 29999})
                        parts = value.split('-', 1)  # Split only on first dash
                        if len(parts) == 2:
                            from_val = int(parts[0].strip())
                            to_val = int(parts[1].strip())
                            value = {"from": from_val, "to": to_val}
                        else:
                            logger.warning("Invalid range format: %s", value)
                    except (ValueError, TypeError) as e:
                        logger.warning("Could not parse range value '%s': %s", value, e)
                else:
                    logger.warning("Range splitting requires string value with '-' separator, got: %s", value)
                    
            elif trans_type == 'set_value':
                # This type is handled differently - it sets a static value
                # and doesn't use the input value at all
                value = transformation.get('value')
                
            else:
                logger.warning("Unknown transformation type: %s", trans_type)
                
        return value

    def _set_nested_value(self, data: Dict[str, Any], path: str, value: Any) -> None:
        """
        Set a value in a nested dictionary using dot notation.
        
        Args:
            data (Dict[str, Any]): The dictionary to modify
            path (str): Dot-separated path (e.g., "vxlan.fabric.name")
            value (Any): The value to set
        """
        keys = path.split('.')
        current = data
        
        # Navigate to the parent of the target key
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
            
        # Set the final value
        current[keys[-1]] = value

    def _render_template(self, template: str, context: Dict[str, Any]) -> str:
        """
        Render a simple Jinja2-like template with the given context.
        
        Args:
            template (str): Template string with {{ variable }} placeholders
            context (Dict[str, Any]): Context variables for template rendering
            
        Returns:
            str: Rendered template string
        """
        result = template
        
        # Find all template variables
        pattern = r'\{\{\s*(\w+)\s*\}\}'
        matches = re.findall(pattern, template)
        
        for var_name in matches:
            if var_name in context:
                placeholder = '{{ ' + var_name + ' }}'
                result = result.replace(placeholder, str(context[var_name]))
            else:
                logger.warning("Template variable '%s' not found in context", var_name)
                
        return result

    def _validate_fabric_type(self, json_data: Dict[str, Any]) -> None:
        """
        Validate that the fabric type is supported for translation.
        
        Args:
            json_data (Dict[str, Any]): The JSON data to validate
            
        Raises:
            ValueError: If the fabric type is not supported
        """
        # Extract the fabric technology friendly name
        fabric_type = self._extract_json_value(json_data, "$.fabricTechnologyFriendly")
        
        if fabric_type is None:
            raise ValueError("Fabric type (fabricTechnologyFriendly) not found in JSON data")
        
        if fabric_type not in self.SUPPORTED_FABRIC_TYPES:
            raise ValueError(
                f"Fabric type '{fabric_type}' is not supported. "
                f"Supported fabric types are: {', '.join(self.SUPPORTED_FABRIC_TYPES)}"
            )
        
        logger.info("Fabric type validation passed: %s", fabric_type)

    def translate_json_data_to_yaml(self, json_data: Dict[str, Any], output_dir: str = ".") -> List[str]:
        """
        Translate JSON data to YAML files based on the mapping configuration.
        
        Args:
            json_data (Dict[str, Any]): The JSON data to translate
            output_dir (str): Output directory for YAML files (default: current directory)
            
        Returns:
            List[str]: List of created YAML file paths
        """
        if not self.map_config:
            logger.error("No mapping configuration loaded")
            return []
        
        # Validate that the fabric type is supported
        try:
            self._validate_fabric_type(json_data)
        except ValueError as e:
            logger.error("Fabric type validation failed: %s", e)
            raise
            
        created_files = []
        
        try:
            # Get output file configurations
            output_files = self.map_config.get('output_files', [])
            
            for file_config in output_files:
                # Extract template variables for filename generation
                template_context = {}
                
                # Build template context from JSON data
                # Look for common fields that might be used in templates
                common_fields = ['fabricName', 'fabricId', 'fabricType']
                for field in common_fields:
                    value = self._extract_json_value(json_data, f"$.{field}")
                    if value:
                        template_context[field] = value
                
                # Generate filename from template
                name_template = file_config.get('name_template', 'output.yaml')
                filename = self._render_template(name_template, template_context)
                
                # Create full path
                full_path = os.path.join(output_dir, filename)
                
                # Ensure directory exists
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                
                # Process mappings for this file
                yaml_data = {}
                mappings = file_config.get('mappings', [])
                
                for mapping in mappings:
                    # Check if this is a set_value mapping (static value)
                    if 'set_value' in mapping:
                        static_value = mapping['set_value']
                        target_path = mapping.get('target_yaml_path')
                        if target_path:
                            self._set_nested_value(yaml_data, target_path, static_value)
                        continue
                    
                    # Regular mapping with source JSON path
                    source_path = mapping.get('source_json_path')
                    target_path = mapping.get('target_yaml_path')
                    transformations = mapping.get('transformations', [])
                    
                    if not source_path or not target_path:
                        logger.warning("Mapping missing source_json_path or target_yaml_path")
                        continue
                    
                    # Extract value from JSON
                    value = self._extract_json_value(json_data, source_path)
                    
                    if value is not None:
                        # Apply transformations
                        transformed_value = self._apply_transformations(value, transformations)
                        
                        # Set value in YAML structure
                        self._set_nested_value(yaml_data, target_path, transformed_value)
                    else:
                        logger.debug("No value found for path: %s", source_path)
                
                # Write YAML file if we have data
                if yaml_data:
                    with open(full_path, 'w', encoding='utf-8') as f:
                        self.yaml.dump(yaml_data, f)
                    
                    logger.info("Created YAML file: %s", full_path)
                    created_files.append(full_path)
                else:
                    logger.warning("No data to write for file: %s", filename)
                    
        except Exception as e:
            logger.error("Error during YAML translation: %s", e)
            
        return created_files
