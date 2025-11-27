#include <linux/seq_file.h>
#include <linux/mmc/host.h>

static int devinfo_read_emmc_func(struct seq_file *s, void *v)
{
	struct mmc_host *mmc = (struct mmc_host *)s->private;
	char *manufacture = NULL;
	if (!mmc) {
		return -EINVAL;
	}
	switch (mmc->card->cid.manfid) {
	case  0x11:
		manufacture = "TOSHIBA";
		break;
	case  0x15:
		manufacture = "SAMSUNG";
		break;
	case  0x45:
		manufacture = "SANDISK";
		break;
	case  0x90:
		manufacture = "HYNIX";
		break;
	case 0xFE:
		manufacture = "ELPIDA";
		break;
	case 0x13:
		manufacture = "MICRON";
		break;
	case 0x9B:
		manufacture = "YMTC";
		break;
	case 0x32:
		manufacture = "PHISON";
		break;
	case 0xD6:
		if (NULL != strstr(mmc->card->cid.prod_name, "C9")) {
			manufacture = "FORESEE";
		} else {
			manufacture = "HG";
		}
		break;
	case 0xf4:
		manufacture = "BIWIN";
		break;
	case 0xab:
		manufacture = "BIWIN";
		break;
	default:
		printk("%s unknown mmc->card->cid.manfid is %x\n", __func__, mmc->card->cid.manfid);
		manufacture = "Unknown";
	}
	seq_printf(s, "Device version:\t\t%s\n", mmc->card->cid.prod_name);
	seq_printf(s, "Device manufacture:\t\t%s\n", manufacture);
	return 0;
}

