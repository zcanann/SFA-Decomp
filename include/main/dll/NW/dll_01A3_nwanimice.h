#ifndef MAIN_DLL_NW_DLL_01A3_NWANIMICE_H_
#define MAIN_DLL_NW_DLL_01A3_NWANIMICE_H_

int nw_animice_SeqFn(void);
int nw_animice_getExtraSize(void);
int nw_animice_getObjectTypeId(void);
void nw_animice_free(int obj);
void nw_animice_render(void);
void nw_animice_hitDetect(void);
void nw_animice_update(void);
void nw_animice_init(int* obj);
void nw_animice_release(void);
void nw_animice_initialise(void);

#endif /* MAIN_DLL_NW_DLL_01A3_NWANIMICE_H_ */
