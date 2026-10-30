<?php

declare(strict_types=1);

namespace AiMcp\Mcp;

/** Holds MCP tool definitions and validates arguments against their (simple) JSON schemas. */
final class ToolRegistry
{
    /** @var array<string, array{definition: array, handler: callable}> */
    private array $tools = [];

    /**
     * @param array<string, array> $properties JSON-schema properties (type, description, default, enum, ...)
     * @param string[] $required
     */
    public function add(
        string $name,
        string $title,
        string $description,
        array $properties,
        array $required,
        callable $handler,
        array $annotations = [],
    ): void {
        $schema = ['type' => 'object', 'properties' => (object) $properties];
        if ($required !== []) {
            $schema['required'] = $required;
        }
        $definition = ['name' => $name, 'title' => $title, 'description' => $description, 'inputSchema' => $schema];
        if ($annotations !== []) {
            $definition['annotations'] = $annotations;
        }
        $this->tools[$name] = ['definition' => $definition, 'handler' => $handler];
    }

    public function definitions(): array
    {
        return array_values(array_map(fn ($t) => $t['definition'], $this->tools));
    }

    public function has(string $name): bool
    {
        return isset($this->tools[$name]);
    }

    /** Runs a tool; returns an MCP CallToolResult. */
    public function call(string $name, array $arguments): array
    {
        $tool = $this->tools[$name];
        try {
            $args = $this->validate($tool['definition']['inputSchema'], $arguments);
            $result = ($tool['handler'])($args);
            $text = is_string($result) ? $result : json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
            return ['content' => [['type' => 'text', 'text' => (string) $text]], 'isError' => false];
        } catch (\Throwable $e) {
            return ['content' => [['type' => 'text', 'text' => 'Error: ' . $e->getMessage()]], 'isError' => true];
        }
    }

    private function validate(array $schema, array $args): array
    {
        $out = [];
        foreach ((array) $schema['properties'] as $key => $prop) {
            if (!array_key_exists($key, $args) || $args[$key] === null) {
                if (array_key_exists('default', $prop)) {
                    $out[$key] = $prop['default'];
                } elseif (in_array($key, $schema['required'] ?? [], true)) {
                    throw new \InvalidArgumentException("Missing required argument \"{$key}\"");
                } else {
                    $out[$key] = null;
                }
                continue;
            }
            $value = $args[$key];
            $type = $prop['type'] ?? null;
            if ($type === 'integer' && is_string($value) && preg_match('/^-?\d+$/', $value)) {
                $value = (int) $value;
            }
            $valid = match ($type) {
                'string' => is_string($value),
                'integer' => is_int($value),
                'boolean' => is_bool($value),
                'object' => is_array($value) && ($value === [] || !array_is_list($value)),
                'array' => is_array($value) && array_is_list($value),
                default => true,
            };
            if (!$valid) {
                throw new \InvalidArgumentException("Argument \"{$key}\" must be of type {$type}");
            }
            if (isset($prop['enum']) && !in_array($value, $prop['enum'], true)) {
                throw new \InvalidArgumentException("Argument \"{$key}\" must be one of: " . implode(', ', $prop['enum']));
            }
            if (isset($prop['minimum']) && $value < $prop['minimum'] || isset($prop['maximum']) && $value > $prop['maximum']) {
                throw new \InvalidArgumentException("Argument \"{$key}\" is out of range");
            }
            $out[$key] = $value;
        }
        return $out;
    }
}
