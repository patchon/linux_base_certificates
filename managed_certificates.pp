#
# This is used to sync certificates to servers. It can, and should, be used to
# sync both certificates and their private key (or single certificates for that
# matter) as well as certificates that should be trusted by the central ca-trust.
#

define linux_base_certificates::managed_certificates(
  $group   = "root",
  $mode    = "0644",
  $owner   = "root",
  $x509    = undef,
  $key     = undef,
  $root_ca = false,
){

  # Define different path's and a specific tag depending on if we are a
  # ca-cert or not,
  if ($root_ca){
    $cert_tag  = "root_ca-$title"
    $cert_path = "/etc/pki/ca-trust/source/anchors"
  }else{
    $cert_tag  = undef
    $cert_path = "/etc/pki/tls/certs"
  }

  # If we have certificate and key,
  if ($x509 and $key){

    # Sync certificate,
    file { "/etc/pki/tls/certs/$title.crt":
      group        => $group,
      mode         => $mode,
      owner        => $owner,
      content      => inline_template($x509),
      validate_cmd => "/bin/openssl x509 -in % &> /dev/null",
    }

    # Sync private key and verify so it matches the with the certificate,
    file { "/etc/pki/tls/private/$title.key":
      group        => $key_group,
      mode         => "0640",
      owner        => $key_owner,
      content      => inline_template($key),
      validate_cmd => "/bin/openssl rsa -in % &> /dev/null &&
                       [[ \"$(openssl rsa  -noout -modulus -in %                             | openssl md5)\" == \
                          \"$(openssl x509 -noout -modulus -in /etc/pki/tls/certs/$title.crt | openssl md5)\" ]]",
      require      => File["/etc/pki/tls/certs/$title.crt"]
    }
  }elsif($x509){

    # We only have a certificate,
    file { "$cert_path/$title.crt":
      group        => $group,
      mode         => $mode,
      owner        => $owner,
      content      => inline_template($x509),
      tag          => $cert_tag,
      validate_cmd => "/bin/openssl x509 -in % &> /dev/null"
    }

    # If we have a certificate of some sort, define exec and associate
    # it by tag below,
    exec { "update-ca-trust-$title":
      command     => '/bin/update-ca-trust',
      refreshonly => true,
    }

    # Set up relationship
    File <| tag == "root_ca-$title" |> ~> Exec["update-ca-trust-$title"]
  }
}
