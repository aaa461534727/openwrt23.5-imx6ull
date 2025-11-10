#ifndef __CS_FIRMWARE_HEADER__
#define __CS_FIRMWARE_HEADER__

#define DL_IMAGE_FILE                                    "/tmp/cloudupdate.web"
#define AUTOUPDATE_SH									 "/tmp/autoupdate.sh"
#define UPDATE_SH										 "/tmp/update.sh"

#define IH_MAGIC    0x27051956
#define IH_NMLEN    32

typedef  enum{
	UPG_FORCE_CHECK=0,
	UPG_UNNET,
	UPG_LATEST,
	UPG_CHECKING,
	UPG_NEW,
	UPG_FORCE_UPGRADEING
}UPG_STATUS;

typedef struct image_header {
    uint32_t    ih_magic;   /* Image Header Magic Number    */
    uint32_t    ih_hcrc;    /* Image Header CRC Checksum    */
    uint32_t    ih_time;    /* Image Creation Timestamp */
    uint32_t    ih_size;    /* Image Data Size      */
    uint32_t    ih_load;    /* Data  Load  Address      */
    uint32_t    ih_ep;      /* Entry Point Address      */
    uint32_t    ih_dcrc;    /* Image Data CRC Checksum  */
    uint8_t     ih_os;      /* Operating System     */
    uint8_t     ih_arch;    /* CPU architecture     */
    uint8_t     ih_type;    /* Image Type           */
    uint8_t     ih_comp;    /* Compression Type     */
    uint8_t     ih_name[IH_NMLEN];  /* Image Name       */
} image_header_t;

extern int firmware_check(char *imagefile, int offset, int len, char *err_msg, char *re_csid);

#endif
