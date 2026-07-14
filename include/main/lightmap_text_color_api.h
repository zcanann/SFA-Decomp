#ifndef MAIN_LIGHTMAP_TEXT_COLOR_API_H_
#define MAIN_LIGHTMAP_TEXT_COLOR_API_H_

void setTextColor(int unused, int red, int green, int blue, int alpha);

#define setTextColorContextLegacy(context, red, green, blue, alpha)                                                     \
    ((void (*)(void*, int, int, int, int))setTextColor)((context), (red), (green), (blue), (alpha))
#define setTextColorByteLegacy(context, color0, color1, color2, alpha)                                                  \
    ((void (*)(void*, unsigned char, unsigned char, unsigned char, int))setTextColor)(                                  \
        (context), (color0), (color1), (color2), (alpha))

#endif /* MAIN_LIGHTMAP_TEXT_COLOR_API_H_ */
