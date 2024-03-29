package influx

import (
	"fmt"
	"reflect"
	"strings"
)

type Tags map[string]string
type Fields map[string]any

type Line struct {
	measurement string
	tags        Tags
	fields      Fields
}

func NewLine(measurement string) *Line {
	line := Line{
		measurement: measurement,
		tags:        make(Tags),
		fields:      make(Fields),
	}

	return &line
}

func (line Line) TagsToString() string {
	items := make([]string, 0)
	for key, value := range line.tags {
		value = strings.ReplaceAll(value, "\\", "\\\\")
		items = append(items, key+"="+strings.ReplaceAll(value, " ", "\\ "))
	}
	return strings.Join(items, ",")
}

func (line Line) FieldsToString() string {
	items := make([]string, 0)
	for key, value := range line.fields {
		if reflect.TypeOf(value).Kind() == reflect.String {
			value = fmt.Sprintf("\"%v\"", value)
		}
		items = append(items, key+"="+fmt.Sprint(value))
	}
	return strings.Join(items, ",")
}

func (line *Line) AddTags(tags Tags) {
	for key, value := range tags {
		line.AddTag(key, value)
	}
}

func (line *Line) AddTag(key string, value any) {
	line.tags[key] = fmt.Sprint(value)
}

func (line *Line) AddField(key string, value any) {
	line.fields[key] = value
}

func (line *Line) AddFields(fields Fields) {
	for key, value := range fields {
		line.AddField(key, value)
	}
}

// TODO: This assumes there is at least 1 tag and 1 field
func (line Line) String() string {
	return fmt.Sprintf("%s,%s %s", line.measurement, line.TagsToString(), line.FieldsToString())
}
