/*
 * Manual recovery stub based on retail source-tag evidence.
 *
 * This file is intentionally not wired into the build yet.
 *
 * Retail source name:
 * - n_attractmode.c
 *
 * Why this stub exists:
 * - Retail EN/source-matrix bundles preserve the source filename, but no
 *   direct current EN xref has been recovered yet.
 * - The best current evidence is an indirect neighborhood spanning
 *   0x8010ACF0-0x80130618 across the CAM/front-end corridor.
 * - Live EN names now anchor the movie side of that corridor:
 *   n_attractmode_releaseMovieBuffers @ 0x8011611C
 *   n_attractmode_prepareMovie @ 0x80116224
 * - Nearby supporting strings include:
 *   /savegame/save%d.bin
 *   PICMENU: tex overflow
 *   malloc for movie failed
 *   starfox.thp
 *   n_rareware
 *
 * Placement note:
 * - Kept at src/n_attractmode.c until a stronger directory/file boundary is
 *   proven.
 */

/*
 * Keep this as a non-built title/movie packet until a tighter source window
 * proves whether the two live movie helpers are the whole file or one island in
 * a larger front-end source.
 */
