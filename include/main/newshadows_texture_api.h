#ifndef MAIN_NEWSHADOWS_TEXTURE_API_H_
#define MAIN_NEWSHADOWS_TEXTURE_API_H_

#include "main/texture.h"

Texture* newshadows_getFalloffTexture(void);
Texture* newshadows_getInverseRampTexture(void);
void allocLotsOfTextures(void);

#endif /* MAIN_NEWSHADOWS_TEXTURE_API_H_ */
