# Boot / loading-screen texture set: the Nintendo, Rareware and Dolby Pro Logic II
# logos, followed by 0xFF padding (the region is reused as the GX FIFO at runtime).
# See docs/orig/embedded_assets.md.
#
# This is a copyrighted embedded asset. Rather than committing its bytes, it is
# reconstructed byte-for-byte at build time by including the corresponding range
# of the user's own retail DOL (orig/GSAE01/sys/main.dol, gitignored). The repo
# holds only this recipe, never the asset. The four symbols carry `noreloc` in
# symbols.txt so dtk emits raw data (the image bytes are not pointers), letting
# this object byte-match the target and count toward the data total.

.section .data

.global gLoadingScreenTextures
gLoadingScreenTextures:
.incbin "orig/GSAE01/sys/main.dol", 0x2C96A0, 0x131E0

.global gRarewareLogoTexture
gRarewareLogoTexture:
.incbin "orig/GSAE01/sys/main.dol", 0x2DC880, 0xA060

.global gDolbyProLogic2Texture
gDolbyProLogic2Texture:
.incbin "orig/GSAE01/sys/main.dol", 0x2E68E0, 0x22E0

.global gLoadingScreenTexturesPad
gLoadingScreenTexturesPad:
.incbin "orig/GSAE01/sys/main.dol", 0x2E8BC0, 0x20AE0
