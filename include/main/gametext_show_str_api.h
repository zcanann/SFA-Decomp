#ifndef MAIN_GAMETEXT_SHOW_STR_API_H_
#define MAIN_GAMETEXT_SHOW_STR_API_H_

typedef void (*GameTextShowStrLegacyFn)(int text, int box, int x, int y);

void gameTextShowStr(char* text, int box, int x, int y);

#define gameTextShowStrLegacy ((GameTextShowStrLegacyFn)gameTextShowStr)

#endif /* MAIN_GAMETEXT_SHOW_STR_API_H_ */
