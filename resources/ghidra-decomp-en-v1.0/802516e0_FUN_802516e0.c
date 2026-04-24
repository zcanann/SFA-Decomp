// Function: FUN_802516e0
// Entry: 802516e0
// Size: 396 bytes

void FUN_802516e0(int param_1)

{
  int iVar1;
  
  do {
    iVar1 = FUN_80250ed0();
  } while (iVar1 == 0);
  FUN_80250ee0();
  FUN_80250ef8(0x80f3a001);
  do {
    iVar1 = FUN_80250ec0();
  } while (iVar1 != 0);
  FUN_80250ef8(*(undefined4 *)(param_1 + 0xc));
  do {
    iVar1 = FUN_80250ec0();
  } while (iVar1 != 0);
  FUN_80250ef8(0x80f3c002);
  do {
    iVar1 = FUN_80250ec0();
  } while (iVar1 != 0);
  FUN_80250ef8(*(uint *)(param_1 + 0x14) & 0xffff);
  do {
    iVar1 = FUN_80250ec0();
  } while (iVar1 != 0);
  FUN_80250ef8(0x80f3a002);
  do {
    iVar1 = FUN_80250ec0();
  } while (iVar1 != 0);
  FUN_80250ef8(*(undefined4 *)(param_1 + 0x10));
  do {
    iVar1 = FUN_80250ec0();
  } while (iVar1 != 0);
  FUN_80250ef8(0x80f3b002);
  do {
    iVar1 = FUN_80250ec0();
  } while (iVar1 != 0);
  FUN_80250ef8(0);
  do {
    iVar1 = FUN_80250ec0();
  } while (iVar1 != 0);
  FUN_80250ef8(0x80f3d001);
  do {
    iVar1 = FUN_80250ec0();
  } while (iVar1 != 0);
  FUN_80250ef8(*(undefined2 *)(param_1 + 0x24));
  do {
    iVar1 = FUN_80250ec0();
  } while (iVar1 != 0);
  FUN_802510cc(s_DSP_is_booting_task__0x_08X_8032e100,param_1);
  FUN_802510cc(s___DSP_boot_task_____IRAM_MMEM_AD_8032e120,*(undefined4 *)(param_1 + 0xc));
  FUN_802510cc(s___DSP_boot_task_____IRAM_DSP_ADD_8032e150,*(undefined4 *)(param_1 + 0x14));
  FUN_802510cc(s___DSP_boot_task_____IRAM_LENGTH___8032e180,*(undefined4 *)(param_1 + 0x10));
  FUN_802510cc(s___DSP_boot_task_____DRAM_MMEM_AD_8032e1b0,*(undefined4 *)(param_1 + 0x1c));
  FUN_802510cc(s___DSP_boot_task_____Start_Vector_8032e1e0,*(undefined2 *)(param_1 + 0x24));
  return;
}

