---
Parameter:
  - ice_pf
Return: void
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_request_fw()
/**
 * ice_request_fw - Device initialization routine
 * @pf: pointer to the PF instance
 */
static void ice_request_fw(struct ice_pf *pf)
{
	char *opt_fw_filename = ice_get_opt_fw_name(pf);
	const struct firmware *firmware = NULL;
	struct device *dev = ice_pf_to_dev(pf);
	int err = 0;

	/* optional device-specific DDP (if present) overrides the default DDP
	 * package file. kernel logs a debug message if the file doesn't exist,
	 * and warning messages for other errors.
	 */
	if (opt_fw_filename) {
		err = firmware_request_nowarn(&firmware, opt_fw_filename, dev);
		if (err) {
			kfree(opt_fw_filename);
			goto dflt_pkg_load;
		}

		/* request for firmware was successful. Download to device */
		ice_load_pkg(firmware, pf);
		kfree(opt_fw_filename);
		release_firmware(firmware);
		return;
	}

dflt_pkg_load:
	err = request_firmware(&firmware, ICE_DDP_PKG_FILE, dev);
	if (err) {
		dev_err(dev, "The DDP package file was not found or could not be read. Entering Safe Mode\n");
		return;
	}

	/* request for firmware was successful. Download to device */
	ice_load_pkg(firmware, pf);
	release_firmware(firmware);
}
```
