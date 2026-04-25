#include "ghidra_import.h"

extern void fn_8003B8F4(double scale);
extern void fn_8012DD7C(int enabled);

extern f32 lbl_803E6618;

typedef struct WorldPlanetState {
  u8 unk0[0x18];
} WorldPlanetState;

int worldplanet_getExtraSize(void)
{
  return sizeof(WorldPlanetState);
}

int worldplanet_func08(void)
{
  return 0;
}

void worldplanet_free(void)
{
  fn_8012DD7C(0);
  return;
}

void worldplanet_render(undefined4 param_1,undefined4 param_2,undefined4 param_3,
                        undefined4 param_4,undefined4 param_5,char visible)
{
  int draw;

  draw = visible;
  if (draw != 0) {
    fn_8003B8F4((double)lbl_803E6618);
  }
  return;
}

void worldplanet_hitDetect(void)
{
  return;
}
