// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DeleteServerVirtualSerialNumber delete server virtual serial number
//
// swagger:model DeleteServerVirtualSerialNumber
type DeleteServerVirtualSerialNumber struct {

	// Indicates if the Virtual Serial Number attached to a PVM Instance is retained or not
	RetainVSN bool `json:"retainVSN,omitempty"`
}

// Validate validates this delete server virtual serial number
func (m *DeleteServerVirtualSerialNumber) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this delete server virtual serial number based on context it is used
func (m *DeleteServerVirtualSerialNumber) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DeleteServerVirtualSerialNumber) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeleteServerVirtualSerialNumber) UnmarshalBinary(b []byte) error {
	var res DeleteServerVirtualSerialNumber
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
