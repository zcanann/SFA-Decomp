// Function: FUN_800e878c
// Entry: 800e878c
// Size: 152 bytes

int FUN_800e878c(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  
  iVar1 = FUN_8007dd3c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&DAT_803a3e24
                      );
  if ((iVar1 == 0) || (DAT_803a3e24 == '\0')) {
    FUN_800033a8(-0x7fc5c1dc,0,0xe4);
    DAT_803a3e2a = 0;
    DAT_803a3e26 = 1;
    DAT_803a3e2c = 1;
    DAT_803a3e24 = '\x01';
    DAT_803a3e2e = 0x7f;
    DAT_803a3e2f = 0x7f;
    DAT_803a3e30 = 0x7f;
  }
  return iVar1;
}

