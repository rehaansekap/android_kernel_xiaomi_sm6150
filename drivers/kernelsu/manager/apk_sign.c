/* Defined further down; needed by the manager-identity pass below. */
static __always_inline bool check_v2_signature(char *path,
					       unsigned expected_size,
					       const char *expected_sha256);

/*
 * ============================================================================
 *  Dynamic manager identity
 * ----------------------------------------------------------------------------
 *  A single kernel build has to satisfy several different manager APKs at once
 *  (KernelSU, KernelSU-Next, BakaSU/ReSukiSU, KowSU, MamboSU, ... and spoofed
 *  re-signs of them). Each manager enforces a *different* expected driver
 *  version code and a different UAPI level, so a hard-coded KSU_VERSION can
 *  only ever match one of them.
 *
 *  Instead of trusting the caller (which can lie) or the package name (which
 *  the user can change), we identify the manager by the SHA-256 of the signing
 *  certificate embedded in its base.apk. The scan is driven by
 *  `ksu_manager_apk_pass()`; on a hit the matching triple
 *  (version, uapi, tag) is latched and handed to userspace by GET_INFO.
 * ============================================================================
 */
enum ksu_manager_type {
	KSU_MANAGER_NONE = 0,
	KSU_MANAGER_OFFICIAL,
	KSU_MANAGER_KSUN,	/* KernelSU-Next, incl. spoofed re-signs */
	KSU_MANAGER_BKSU,	/* BakaSU / ReSukiSU */
	KSU_MANAGER_KOWSU,	/* KowSU */
	KSU_MANAGER_MAMBO,	/* MamboSU */
};

struct ksu_known_manager {
	enum ksu_manager_type type;
	const char *hash;	/* SHA-256 of the APK signing certificate, hex */
	u32 version;		/* version code the manager expects from the driver */
	const char *tag;	/* human readable version tag */
	u32 uapi;		/* UAPI level the manager's ksud was built against */
};

/*
 * Certificate hashes below were read out of the real manager APKs with
 * `apksigner verify --print-certs`, and the UAPI level with
 * `strings libksud.so | grep 'uapi:'`. Keep them in sync when bumping a
 * manager: a wrong hash only means "manager not recognised as itself", but a
 * wrong uapi makes ksud abort module installs.
 */
static const struct ksu_known_manager ksu_known_managers[] = {
	/* v3.3.1+20 / 32700, ksud "3.3.1+20 (uapi: 6)", CN=first last */
	{ KSU_MANAGER_OFFICIAL, "4359c171f32543394cbc23ef908c4bb94cad7c8087002ba164c8230948c21549", 32700, "v3.3.1", 6 },
	/* v3.4.2-50 / 33405, ksud "3.4.2-50-gb427a3f9 (uapi: 6)", CN=Rifat Azad */
	{ KSU_MANAGER_KSUN, "79e590113c4c4c0c222978e413a5faa801666957b1212a328e46c00c69821bf7", 33405, "v3.4.2", 6 },
	/* v4.2.0-rc3 / 35235, ksud "4.2.0-rc3-64-g7c383cfe (uapi: 5)", CN=ReSukiSU */
	{ KSU_MANAGER_BKSU, "d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64", 35235, "v4.2.0", 5 },
	/* v3.3.0-131 / 32732, ksud "3.3.0-131-g8cd02474 (uapi: 6)", CN=kowx712 */
	{ KSU_MANAGER_KOWSU, "484fcba6e6c43b1fb09700633bf2fb4758f13cb0b2f4457b80d075084b26c588", 32732, "v3.3.0", 6 },
	/* v3.3.0-17 / 32653, ksud "3.3.0-17-geacec300 (uapi: 5)", CN=Rafi */
	{ KSU_MANAGER_MAMBO, "a9462b8b98ea1ca7901b0cbdcebfaa35f0aa95e51b01d66e6b6d2c81b97746d8", 32653, "v3.3.0", 5 },
};

/*
 * Managers we can recognise (so they may still be crowned and get root) but
 * whose expected driver version / UAPI we have not collected yet. A hit here
 * does not touch the identity triple reported by GET_INFO.
 */
static const char * const ksu_extra_manager_hashes[] = {
	/* rsuntk/KernelSU */
	"f415f4ed9435427e1fdf7f1fccd4dbc07b3d6b8751e4dbcec6f19671f427870b",
	/* WildKernels/Wild_KSU */
	"52d52d8c8bfbe53dc2b6ff1c613184e2c03013e090fe8905d8e3d5dc2658c2e4",
};

static enum ksu_manager_type ksu_detected_manager = KSU_MANAGER_NONE;
static u32 ksu_detected_version = KSU_VERSION;
static u32 ksu_detected_uapi = KERNEL_SU_UAPI_VERSION;
static const char *ksu_detected_tag = KSU_VERSION_TAG;

/* Called from check_block() with the SHA-256 of a candidate certificate. */
static bool ksu_record_manager_by_cert(const char *hash_str)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ksu_known_managers); i++) {
		const struct ksu_known_manager *m = &ksu_known_managers[i];

		if (strcmp(m->hash, hash_str))
			continue;

		ksu_detected_manager = m->type;
		ksu_detected_version = m->version;
		ksu_detected_uapi = m->uapi;
		ksu_detected_tag = m->tag;
		pr_info("ksu: manager recognised: type=%d version=%u tag=%s uapi=%u\n",
			m->type, m->version, m->tag, m->uapi);
		return true;
	}

	for (i = 0; i < ARRAY_SIZE(ksu_extra_manager_hashes); i++) {
		if (strcmp(ksu_extra_manager_hashes[i], hash_str))
			continue;

		pr_info("ksu: manager recognised (identity unknown): %s\n",
			hash_str);
		return true;
	}

	return false;
}

/*
 * Fall back to the driver's own identity when the manager still refuses to
 * talk to us (unknown/self-signed manager, or the throne tracker has not run
 * yet). Returning false keeps the caller's previous state untouched.
 */
bool ksu_manager_identity_known(void)
{
	return ksu_detected_manager != KSU_MANAGER_NONE;
}

u32 ksu_get_manager_version(void)
{
	return ksu_detected_version;
}

u32 ksu_get_manager_uapi_version(void)
{
	return ksu_detected_uapi;
}

const char *ksu_get_manager_version_tag(void)
{
	return ksu_detected_tag;
}

/*
 * Fallback identity: respect whatever KSU_VERSION the manager pushed via the
 * CHANGE_KSUVER supercall, but only while we have no certificate-based
 * identification yet (a real manager always wins).
 */
void ksu_set_fallback_version(u32 version)
{
	if (ksu_detected_manager == KSU_MANAGER_NONE)
		ksu_detected_version = version;
}

static bool ksu_manager_apk_pass(const char *path);

struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	int size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kzalloc(size, GFP_KERNEL);
	if (!sdesc)
		return ERR_PTR(-ENOMEM);
	sdesc->shash.tfm = alg;
	return sdesc;
}

static int calc_hash(struct crypto_shash *alg, const unsigned char *data,
		     unsigned int datalen, unsigned char *digest)
{
	struct sdesc *sdesc;
	int ret;

	sdesc = init_sdesc(alg);
	if (IS_ERR(sdesc)) {
		pr_info("can't alloc sdesc\n");
		return PTR_ERR(sdesc);
	}

	ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
	kfree(sdesc);
	return ret;
}

static int ksu_sha256(const unsigned char *data, unsigned int datalen,
		      unsigned char *digest)
{
	struct crypto_shash *alg;
	char *hash_alg_name = "sha256";
	int ret;

	alg = crypto_alloc_shash(hash_alg_name, 0, 0);
	if (IS_ERR(alg)) {
		pr_info("can't alloc alg %s\n", hash_alg_name);
		return PTR_ERR(alg);
	}
	ret = calc_hash(alg, data, datalen, digest);
	crypto_free_shash(alg);
	return ret;
}

static bool check_block(struct file *fp, u32 *size4, loff_t *pos, u32 *offset,
			unsigned expected_size, const char *expected_sha256)
{
	kernel_read(fp, size4, 0x4, pos); // signer-sequence length
	kernel_read(fp, size4, 0x4, pos); // signer length
	kernel_read(fp, size4, 0x4, pos); // signed data length

	*offset += 0x4 * 3;

	kernel_read(fp, size4, 0x4, pos); // digests-sequence length

	*pos += *size4;
	*offset += 0x4 + *size4;

	kernel_read(fp, size4, 0x4, pos); // certificates length
	kernel_read(fp, size4, 0x4, pos); // certificate length
	*offset += 0x4 * 2;

	/*
	 * NOTE: filter mode.
	 *   expected_size != 0 -> legacy behaviour: only hash certs whose DER
	 *                         length matches (each manager is tried with its
	 *                         own size, so most blocks are skipped early).
	 *   expected_size == 0 -> match purely on the certificate SHA-256 and,
	 *                         on a hit, record which manager was detected.
	 *                         This is what lets a single pass recognise every
	 *                         supported manager (KSUNext/BakaSU/KowSU/MamboSU
	 *                         and their spoofed re-signs) regardless of the
	 *                         certificate length, which varies per build.
	 */
	if (expected_size == 0 || *size4 == expected_size) {
		*offset += *size4;

#define CERT_MAX_LENGTH 1024
		char *cert __attribute__((__cleanup__(ksu_kfree_byref))) = kzalloc(CERT_MAX_LENGTH, GFP_KERNEL);
		if (!cert)
			return false;

		if (*size4 > CERT_MAX_LENGTH) {
			pr_info("cert length overlimit\n");
			return false;
		}
		kernel_read(fp, cert, *size4, pos);
		unsigned char digest[SHA256_DIGEST_SIZE];
		if (ksu_sha256(cert, *size4, digest) < 0 ) {
			pr_info("sha256 error\n");
			return false;
		}

		char hash_str[SHA256_DIGEST_SIZE * 2 + 1];
		hash_str[SHA256_DIGEST_SIZE * 2] = '\0';

		bin2hex(hash_str, digest, SHA256_DIGEST_SIZE);
		pr_info("sha256: %s, expected: %s\n", hash_str,
			expected_size ? expected_sha256 : "(any known manager)");
		if (expected_size) {
			if (strcmp(expected_sha256, hash_str) == 0) {
				return true;
			}
		} else if (ksu_record_manager_by_cert(hash_str)) {
			return true;
		}
	}
	return false;
}

struct zip_entry_header {
	uint32_t signature;
	uint16_t version;
	uint16_t flags;
	uint16_t compression;
	uint16_t mod_time;
	uint16_t mod_date;
	uint32_t crc32;
	uint32_t compressed_size;
	uint32_t uncompressed_size;
	uint16_t file_name_length;
	uint16_t extra_field_length;
} __attribute__((packed));

// This is a necessary but not sufficient condition, but it is enough for us
static bool has_v1_signature_file(struct file *fp)
{
	struct zip_entry_header header;
	const char MANIFEST[] = "META-INF/MANIFEST.MF";

	loff_t pos = 0;

	while (kernel_read(fp, &header,
				      sizeof(struct zip_entry_header), &pos) ==
	       sizeof(struct zip_entry_header)) {
		if (header.signature != 0x04034b50) {
			// ZIP magic: 'PK'
			return false;
		}
		// Read the entry file name
		if (header.file_name_length == sizeof(MANIFEST) - 1) {
			char fileName[sizeof(MANIFEST)];
			kernel_read(fp, fileName,
					       header.file_name_length, &pos);
			fileName[header.file_name_length] = '\0';

			// Check if the entry matches META-INF/MANIFEST.MF
			if (strncmp(MANIFEST, fileName, sizeof(MANIFEST) - 1) ==
			    0) {
				return true;
			}
		} else {
			// Skip the entry file name
			pos += header.file_name_length;
		}

		// Skip to the next entry
		pos += header.extra_field_length + header.compressed_size;
	}

	return false;
}

static __always_inline bool check_v2_signature(char *path,
					       unsigned expected_size,
					       const char *expected_sha256)
{
	unsigned char buffer[0x11] = { 0 };
	u32 size4;
	u64 size8, size_of_block;

	loff_t pos;

	bool v2_signing_valid = false;
	int v2_signing_blocks = 0;
	bool v3_signing_exist = false;
	bool v3_1_signing_exist = false;

	int i;

	struct path kpath;
	if (kern_path(path, 0, &kpath))
		return false;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0) 
	if (inode_is_locked(kpath.dentry->d_inode))
#else
	if (mutex_is_locked(&kpath.dentry->d_inode->i_mutex))
#endif
	{
		pr_info("%s: inode is locked for %s\n", __func__, path);
		path_put(&kpath);
		return false;
	}

	path_put(&kpath);

	struct file *fp = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		// pr_err("open %s error.\n", path);
		return false;
	}

	// disable inotify for this file
	fp->f_mode |= FMODE_NONOTIFY;

	// https://en.wikipedia.org/wiki/Zip_(file_format)#End_of_central_directory_record_(EOCD)
	for (i = 0;; ++i) {
		unsigned short n;
		pos = vfs_llseek(fp, -i - 2, SEEK_END);
		kernel_read(fp, &n, 2, &pos);
		if (n == i) {
			pos -= 22;
			kernel_read(fp, &size4, 4, &pos);
			if ((size4 ^ 0xcafebabeu) == 0xccfbf1eeu) {
				break;
			}
		}
		if (i == 0xffff) {
			pr_info("error: cannot find eocd\n");
			goto clean;
		}
	}

	pos += 12;
	// offset
	kernel_read(fp, &size4, 0x4, &pos);
	pos = size4 - 0x18;

	kernel_read(fp, &size8, 0x8, &pos);
	kernel_read(fp, buffer, 0x10, &pos);
	if (memcmp(buffer, "APK Sig Block 42", 16)) {
		goto clean;
	}

	pos = size4 - (size8 + 0x8);
	kernel_read(fp, &size_of_block, 0x8, &pos);
	if (size_of_block != size8) {
		goto clean;
	}

	int loop_count = 0;
	while (loop_count++ < 10) {
		uint32_t id;
		uint32_t offset;
		kernel_read(fp, &size8, 0x8, &pos); // sequence length
		if (size8 == size_of_block) {
			break;
		}
		kernel_read(fp, &id, 0x4, &pos); // id
		offset = 4;
		if (id == 0x7109871au) {
			v2_signing_blocks++;
			v2_signing_valid =
				check_block(fp, &size4, &pos, &offset,
					    expected_size, expected_sha256);
		} else if (id == 0xf05368c0u) {
			// http://aospxref.com/android-14.0.0_r2/xref/frameworks/base/core/java/android/util/apk/ApkSignatureSchemeV3Verifier.java#73
			v3_signing_exist = true;
		} else if (id == 0x1b93ad61u) {
			// http://aospxref.com/android-14.0.0_r2/xref/frameworks/base/core/java/android/util/apk/ApkSignatureSchemeV3Verifier.java#74
			v3_1_signing_exist = true;
		} else {
#ifdef CONFIG_KSU_DEBUG
			pr_info("Unknown id: 0x%08x\n", id);
#endif
		}
		pos += (size8 - offset);
	}

	if (v2_signing_blocks != 1) {
#ifdef CONFIG_KSU_DEBUG
		pr_err("Unexpected v2 signature count: %d\n",
		       v2_signing_blocks);
#endif
		v2_signing_valid = false;
	}

	if (v2_signing_valid) {
		int has_v1_signing = has_v1_signature_file(fp);
		if (has_v1_signing) {
			pr_err("Unexpected v1 signature scheme found!\n");
			filp_close(fp, 0);
			return false;
		}
	}
clean:
	filp_close(fp, 0);

	if (v3_signing_exist || v3_1_signing_exist) {
#ifdef CONFIG_KSU_DEBUG
		pr_err("Unexpected v3 signature scheme found!\n");
#endif
		return false;
	}

	return v2_signing_valid;
}

static bool ksu_manager_apk_pass(const char *path)
{
	/* expected_size 0 => match on certificate hash only, record identity */
	return check_v2_signature((char *)path, 0, NULL);
}

#ifdef CONFIG_KSU_DEBUG

int ksu_debug_manager_appid = -1;

static int set_expected_size(const char *val, const struct kernel_param *kp)
{
	int rv = param_set_uint(val, kp);
	ksu_set_manager_appid(ksu_debug_manager_appid);
	pr_info("ksu_manager_appid set to %d\n", ksu_debug_manager_appid);
	return rv;
}

static struct kernel_param_ops expected_size_ops = {
	.set = set_expected_size,
	.get = param_get_uint,
};

module_param_cb(ksu_debug_manager_appid, &expected_size_ops,
	&ksu_debug_manager_appid, S_IRUSR | S_IWUSR);

#endif

int get_pkg_from_apk_path(char *pkg, const char *path)
{
	int len = strlen(path);
	if (len >= KSU_MAX_PACKAGE_NAME || len < 1)
		return -1;

	const char *last_slash = NULL;
	const char *second_last_slash = NULL;

	int i;
	for (i = len - 1; i >= 0; i--) {
		if (path[i] == '/') {
			if (!last_slash) {
				last_slash = &path[i];
			} else {
				second_last_slash = &path[i];
				break;
			}
		}
	}

	if (!last_slash || !second_last_slash)
		return -1;

	const char *last_hyphen = strchr(second_last_slash, '-');
	if (!last_hyphen || last_hyphen > last_slash)
		return -1;

	int pkg_len = last_hyphen - second_last_slash - 1;
	if (pkg_len >= KSU_MAX_PACKAGE_NAME || pkg_len <= 0)
		return -1;

	// Copying the package name
	memcpy(pkg, second_last_slash + 1, pkg_len);
	pkg[pkg_len] = '\0';

	return 0;
}

bool is_manager_apk(char *path)
{
#ifdef KSU_MANAGER_PACKAGE
	char pkg[KSU_MAX_PACKAGE_NAME];
	if (get_pkg_from_apk_path(pkg, path) < 0) {
		pr_err("Failed to get package name from apk path: %s\n", path);
		return false;
	}

	// pkg is `<real package>`
	if (strncmp(pkg, KSU_MANAGER_PACKAGE, sizeof(KSU_MANAGER_PACKAGE))) {
		return false;
	}
#endif

	/*
	 * Identify the manager by certificate only (no size filter, no package
	 * name filter) and latch its identity as a side effect. Every supported
	 * manager is present in ksu_known_managers[], so a hit here also tells
	 * GET_INFO which version/UAPI triple to report.
	 */
	return ksu_manager_apk_pass(path);
}
