#
# This class will create certificates based upon hiera data.
# The way that works is described in linux_base_certificates::managed_certificates
#

class linux_base_certificates::create {

  # Gather certificate information from hiera and sync them thereafter
  $certificates = hiera_hash("linux_base_certificates::managed_certificates", {})
  create_resources("linux_base_certificates::managed_certificates",$certificates)
}
