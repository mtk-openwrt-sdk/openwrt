#FIT loadaddr
KERNEL_LOADADDR := 0x41080000

define Device/MTK-AC2600-RFB1
  DEVICE_TITLE := MTK7622 ac2600 RFB1 AP
  DEVICE_DTS := mt7622-ac2600rfb1
  DEVICE_DTS_DIR := $(DTS_DIR)/mediatek
  DEVICE_PACKAGES := kmod-usb-core kmod-usb-ohci kmod-usb-storage kmod-usb2 kmod-usb3 \
			kmod-ata-core kmod-ata-ahci-mtk \
			wireless-tools block-mount luci luci-app-mtk luci-app-samba \
			ppp-mod-pppol2tp ppp-mod-pptp switch qdma \
			kmod-sdhci-mtk
endef
TARGET_DEVICES += MTK-AC2600-RFB1

define Device/MTK-AC4300-RFB1
  DEVICE_TITLE := MTK7622 ac4300 RFB1 AP
  DEVICE_DTS := mt7622-ac4300rfb1
  DEVICE_DTS_DIR := $(DTS_DIR)/mediatek
  DEVICE_PACKAGES := kmod-usb-core kmod-usb-ohci kmod-usb-storage kmod-usb2 kmod-usb3 \
			wireless-tools block-mount luci luci-app-mtk luci-app-samba \
			ppp-mod-pppol2tp ppp-mod-pptp switch qdma \
			kmod-sdhci-mtk
endef
TARGET_DEVICES += MTK-AC4300-RFB1

define Device/MTK-AC4300-Raeth
  DEVICE_TITLE := MTK7622 ac4300 Raeth version
  DEVICE_DTS := mt7622-ac4300-raeth
  DEVICE_DTS_DIR := $(DTS_DIR)/mediatek
  DEVICE_PACKAGES := kmod-usb-core kmod-usb-ohci kmod-usb-storage kmod-usb2 kmod-usb3 \
			wireless-tools block-mount luci luci-app-mtk luci-app-samba \
			ppp-mod-pppol2tp ppp-mod-pptp switch qdma \
			kmod-sdhci-mtk
endef
TARGET_DEVICES += MTK-AC4300-Raeth

define Device/MTK-AC2600-Raeth
  DEVICE_TITLE := MTK7622 ac2600 Raeth version
  DEVICE_DTS := mt7622-ac2600-raeth
  DEVICE_DTS_DIR := $(DTS_DIR)/mediatek
  DEVICE_PACKAGES := kmod-usb-core kmod-usb-ohci kmod-usb-storage kmod-usb2 kmod-usb3 \
                        wireless-tools block-mount luci luci-app-mtk luci-app-samba \
                        ppp-mod-pppol2tp ppp-mod-pptp switch qdma \
                        kmod-sdhci-mtk
endef
TARGET_DEVICES += MTK-AC2600-Raeth

define Device/MTK-AX3600
  DEVICE_TITLE := MTK7622 AX3600 AP
  DEVICE_DTS := mt7622-ax3600
  DEVICE_DTS_DIR := $(DTS_DIR)/mediatek
  DEVICE_PACKAGES := kmod-usb-core kmod-usb-ohci kmod-usb-storage kmod-usb2 kmod-usb3 \
                        wireless-tools block-mount luci luci-app-mtk luci-app-samba \
                        ppp-mod-pppol2tp ppp-mod-pptp switch qdma \
                        kmod-sdhci-mtk
endef
TARGET_DEVICES += MTK-AX3600

define Device/MTK-AC4300-LYNX
  DEVICE_TITLE := MTK7622 ac4300 lynx RFB
  DEVICE_DTS := mt7622-lynx-ac4300rfb1
  DEVICE_DTS_DIR := $(DTS_DIR)/mediatek
  DEVICE_PACKAGES := kmod-usb-core kmod-usb-ohci kmod-usb-storage kmod-usb2 kmod-usb3 \
			wireless-tools block-mount luci luci-app-mtk luci-app-samba \
			ppp-mod-pppol2tp ppp-mod-pptp switch qdma \
			kmod-sdhci-mtk
endef
TARGET_DEVICES += MTK-AC4300-LYNX

define Device/MTK-AC2600-LYNX
  DEVICE_TITLE := MTK7622 ac2600 lynx RFB
  DEVICE_DTS := mt7622-lynx-ac2600rfb1
  DEVICE_DTS_DIR := $(DTS_DIR)/mediatek
  DEVICE_PACKAGES := kmod-usb-core kmod-usb-ohci kmod-usb-storage kmod-usb2 kmod-usb3 \
			wireless-tools block-mount luci luci-app-mtk luci-app-samba \
			ppp-mod-pppol2tp ppp-mod-pptp switch qdma \
			kmod-sdhci-mtk
endef
TARGET_DEVICES += MTK-AC2600-LYNX

