package provider

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceRSAPrivateKey() *schema.Resource {
	return &schema.Resource{
		Description: "Converts a RSA private key (e.g. from `PKCS#1` to `PKCS#8`).",

		ReadContext: dataSourceRSAPrivateKeyRead,

		Schema: map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeString,
				Description: "A unique id for the converted private key.",
				Computed:    true,
			},

			"input_format": {
				Type: schema.TypeString,
				Description: "The format of the provided private key.\n" +
					"  \n" +
					"  Supported formats: `PKCS#1`, `PKCS#8`.",
				Required: true,
			},
			"input_pem": {
				Type:        schema.TypeString,
				Description: "The private key, encoded as `PEM`.",
				Required:    true,
				Sensitive:   true,
			},
			"output_format": {
				Type: schema.TypeString,
				Description: "The format to convert the private key to.\n" +
					"  \n" +
					"  Supported formats: `PKCS#1`, `PKCS#8`.",
				Required: true,
			},
			"output_pem": {
				Type:        schema.TypeString,
				Description: "The converted private key, encoded as `PEM`.",
				Computed:    true,
				Sensitive:   true,
			},
		},
	}
}

func dataSourceRSAPrivateKeyRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	privateKey, err := decodeRSAPrivateKey(d.Get("input_format").(string), d.Get("input_pem").(string))
	if err != nil {
		return diag.Errorf("Could not decode private key: %v", err)
	}

	output, err := encodeRSAPrivateKey(d.Get("output_format").(string), privateKey)
	if err != nil {
		return diag.Errorf("Could not encode private key: %v", err)
	}
	d.SetId(computeHash(output))
	d.Set("output_pem", output)

	return nil
}

func decodeRSAPrivateKey(format string, data string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(data))

	switch format {
	case "PKCS#1":
		return x509.ParsePKCS1PrivateKey(block.Bytes)

	case "PKCS#8":
		{
			rawKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			key, ok := rawKey.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("Illegal key for format PKCS#8")
			}
			return key, nil
		}

	default:
		return nil, fmt.Errorf("Unknown format %v", format)
	}
}

func encodeRSAPrivateKey(format string, privateKey *rsa.PrivateKey) (string, error) {
	var block *pem.Block
	switch format {
	case "PKCS#1":
		block = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}

	case "PKCS#8":
		{
			bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
			if err != nil {
				return "", err
			}
			block = &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: bytes,
			}
		}

	default:
		return "", fmt.Errorf("Unknown format %v", format)
	}

	return string(pem.EncodeToMemory(block)), nil
}

func computeHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
