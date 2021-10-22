terraform {
  required_providers {
    tlsconvert = {
      source = "engflow/tlsconvert"
    }
  }
}

provider "tlsconvert" {
}

resource "tls_private_key" "key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

data "tlsconvert_rsa_private_key" "example" {
  input_format = "PKCS#1"
  input_pem    = tls_private_key.key.private_key_pem

  output_format = "PKCS#8"
}
