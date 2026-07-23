#ifndef MAIN_TEXTRENDER_INTERNAL_H_
#define MAIN_TEXTRENDER_INTERNAL_H_

#include "main/texture.h"

typedef struct GlyphResource802CA100 {
    u16 rows0[320];
    void* embedded;
    u16 rows1[78];
} GlyphResource802CA100;

extern s16 gGameTextBoxTexAssets;
extern u16 gGameTextBoxCornerTexSrc[256];
extern GlyphResource802CA100 lbl_802CA100;
extern Texture* gGameTextBoxCornerTexture;
extern Texture* gGameTextBoxBgTexture;
extern Texture* gGameTextBoxEdgeTexture;

#endif /* MAIN_TEXTRENDER_INTERNAL_H_ */
