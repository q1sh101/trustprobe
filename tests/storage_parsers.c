#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "assert_helpers.h"
#include "storage_parsers.h"

int main(void) {
    trustprobe_lsblk_posture_t posture = {0};

    trustprobe_parse_lsblk_posture(
        "NAME=\"nvme0n1p7\" TYPE=\"part\" FSTYPE=\"crypto_LUKS\"\n"
        "NAME=\"cryptroot\" TYPE=\"crypt\" FSTYPE=\"ext4\"\n",
        &posture
    );
    assert_eq_sz("luks_count", posture.luks_count, 1);
    assert_eq_sz("crypt_count", posture.crypt_count, 1);
    assert_eq_sz("crypt_swap_count_when_luks_present", posture.crypt_swap_count, 0);

    trustprobe_parse_lsblk_posture(
        "NAME=\"cryptswap\" TYPE=\"crypt\" FSTYPE=\"swap\"\n",
        &posture
    );
    assert_eq_sz("crypt_only_luks_count", posture.luks_count, 0);
    assert_eq_sz("crypt_only_crypt_count", posture.crypt_count, 1);
    assert_eq_sz("crypt_only_swap_count", posture.crypt_swap_count, 1);

    trustprobe_parse_lsblk_posture(
        "NAME=\"cryptdata\" TYPE=\"crypt\" FSTYPE=\"ext4\"\n",
        &posture
    );
    assert_eq_sz("crypt_data_luks_count", posture.luks_count, 0);
    assert_eq_sz("crypt_data_crypt_count", posture.crypt_count, 1);
    assert_eq_sz("crypt_data_swap_count", posture.crypt_swap_count, 0);

    trustprobe_parse_lsblk_posture(
        "NAME=\"nvme0n1p1\" TYPE=\"part\" FSTYPE=\"vfat\"\n"
        "NAME=\"nvme0n1p2\" TYPE=\"part\" FSTYPE=\"ext4\"\n",
        &posture
    );
    assert_eq_sz("plain_luks_count", posture.luks_count, 0);
    assert_eq_sz("plain_crypt_count", posture.crypt_count, 0);
    assert_eq_sz("plain_crypt_swap_count", posture.crypt_swap_count, 0);

    /* long line: >512 bytes should not split into multiple logical lines */
    {
        char long_input[1024];
        memset(long_input, 'X', sizeof(long_input));
        /* Keep marker early; this isolates cursor advancement after truncation. */
        const char *marker = "NAME=\"long\" TYPE=\"part\" FSTYPE=\"crypto_LUKS\"";
        size_t mlen = strlen(marker);
        memcpy(long_input, marker, mlen);
        long_input[sizeof(long_input) - 2] = '\n';
        long_input[sizeof(long_input) - 1] = '\0';

        trustprobe_parse_lsblk_posture(long_input, &posture);
        assert_eq_sz("long_line_luks_count", posture.luks_count, 1);
        assert_eq_sz("long_line_crypt_count", posture.crypt_count, 0);
    }

    uint32_t mask = 0;

    assert_true("pcr_pcr7_only",
        trustprobe_parse_luks_pcr_mask(
            "Tokens:\n  0: systemd-tpm2\n     Keyslot: 0\n     pcrs: 7\n",
            &mask));
    assert_eq_int("pcr_pcr7_only_value", (int)mask, (int)(1u << 7));

    assert_true("pcr_multi",
        trustprobe_parse_luks_pcr_mask(
            "Tokens:\n  0: systemd-tpm2\n     Keyslot: 0\n     pcrs: 0 4 7 9\n",
            &mask));
    assert_eq_int("pcr_multi_value", (int)mask,
        (int)((1u << 0) | (1u << 4) | (1u << 7) | (1u << 9)));

    assert_true("pcr_json_array",
        trustprobe_parse_luks_pcr_mask(
            "  0: systemd-tpm2\n     \"tpm2-pcrs\": [7, 9]\n",
            &mask));
    assert_eq_int("pcr_json_array_value", (int)mask,
        (int)((1u << 7) | (1u << 9)));

    assert_false("pcr_no_tpm2_token",
        trustprobe_parse_luks_pcr_mask(
            "Tokens:\n  0: clevis\n     Keyslot: 0\n     pcrs: 7\n",
            &mask));

    assert_false("pcr_no_pcrs_key",
        trustprobe_parse_luks_pcr_mask(
            "Tokens:\n  0: systemd-tpm2\n     Keyslot: 0\n",
            &mask));

    assert_false("pcr_null", trustprobe_parse_luks_pcr_mask(NULL, &mask));
    assert_false("pcr_null_out", trustprobe_parse_luks_pcr_mask("systemd-tpm2\n", NULL));

    printf("storage parsers ok\n");
    return 0;
}
