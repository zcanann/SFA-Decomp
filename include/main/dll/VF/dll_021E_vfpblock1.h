#ifndef MAIN_DLL_VF_DLL_021E_VFPBLOCK1_H_
#define MAIN_DLL_VF_DLL_021E_VFPBLOCK1_H_

typedef struct GameObject GameObject;

int VFP_Block1_getExtraSize(void);
int VFP_Block1_getObjectTypeId(void);
void VFP_Block1_free(int obj);
void VFP_Block1_render(void);
void VFP_Block1_hitDetect(void);
void VFP_Block1_update(GameObject* obj);
void VFP_Block1_init(int obj, int data);
void VFP_Block1_release(void);
void VFP_Block1_initialise(void);

#endif /* MAIN_DLL_VF_DLL_021E_VFPBLOCK1_H_ */
