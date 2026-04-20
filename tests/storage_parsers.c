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

    printf("storage parsers ok\n");
    return 0;
}
