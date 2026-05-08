#ifndef MAIN_DLL_DR_DRCLOUDBALL_H_
#define MAIN_DLL_DR_DRCLOUDBALL_H_

#include "ghidra_import.h"

void spscarab_update(int param_1);
void spscarab_init(int param_1, int param_2);
void spscarab_release(void);
void spscarab_initialise(void);
int spdrape_getExtraSize(void);
int spdrape_func08(void);
void spdrape_free(void);
void spdrape_render(void);
void spdrape_hitDetect(void);

#endif /* MAIN_DLL_DR_DRCLOUDBALL_H_ */
