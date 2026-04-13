// Function: FUN_8027979c
// Entry: 8027979c
// Size: 852 bytes

void FUN_8027979c(int param_1)

{
  undefined4 *puVar1;
  int iVar2;
  
  if (*(int *)(param_1 + 0xf4) != -1) {
    FUN_8027aa18(param_1);
    if (*(uint *)(param_1 + 0xf0) == 0xffffffff) {
      if (*(int *)(param_1 + 0xec) == -1) {
        puVar1 = *(undefined4 **)(param_1 + 0xf8);
        if (puVar1 == *(undefined4 **)(param_1 + 0xfc)) {
          if ((undefined4 *)puVar1[1] == (undefined4 *)0x0) {
            DAT_803def74 = *puVar1;
          }
          else {
            *(undefined4 *)puVar1[1] = *puVar1;
          }
          iVar2 = **(int **)(param_1 + 0xf8);
          if (iVar2 != 0) {
            *(int *)(iVar2 + 4) = (*(int **)(param_1 + 0xf8))[1];
          }
          **(int **)(param_1 + 0xf8) = DAT_803def78;
          if (DAT_803def78 != 0) {
            *(undefined4 *)(DAT_803def78 + 4) = *(undefined4 *)(param_1 + 0xf8);
          }
          *(undefined4 *)(*(int *)(param_1 + 0xf8) + 4) = 0;
          DAT_803def78 = *(int *)(param_1 + 0xf8);
          *(undefined4 *)(param_1 + 0xf8) = 0;
          *(undefined4 *)(param_1 + 0xfc) = 0;
        }
        else {
          if ((undefined4 *)puVar1[1] == (undefined4 *)0x0) {
            DAT_803def74 = *puVar1;
          }
          else {
            *(undefined4 *)puVar1[1] = *puVar1;
          }
          iVar2 = **(int **)(param_1 + 0xf8);
          if (iVar2 != 0) {
            *(int *)(iVar2 + 4) = (*(int **)(param_1 + 0xf8))[1];
          }
          **(int **)(param_1 + 0xf8) = DAT_803def78;
          if (DAT_803def78 != 0) {
            *(undefined4 *)(DAT_803def78 + 4) = *(undefined4 *)(param_1 + 0xf8);
          }
          *(undefined4 *)(*(int *)(param_1 + 0xf8) + 4) = 0;
          DAT_803def78 = *(int *)(param_1 + 0xf8);
          *(undefined4 *)(param_1 + 0xf8) = 0;
          puVar1 = *(undefined4 **)(param_1 + 0xfc);
          if ((undefined4 *)puVar1[1] == (undefined4 *)0x0) {
            DAT_803def74 = *puVar1;
          }
          else {
            *(undefined4 *)puVar1[1] = *puVar1;
          }
          iVar2 = **(int **)(param_1 + 0xfc);
          if (iVar2 != 0) {
            *(int *)(iVar2 + 4) = (*(int **)(param_1 + 0xfc))[1];
          }
          **(int **)(param_1 + 0xfc) = DAT_803def78;
          if (DAT_803def78 != 0) {
            *(undefined4 *)(DAT_803def78 + 4) = *(undefined4 *)(param_1 + 0xfc);
          }
          *(undefined4 *)(*(int *)(param_1 + 0xfc) + 4) = 0;
          DAT_803def78 = *(int *)(param_1 + 0xfc);
          *(undefined4 *)(param_1 + 0xfc) = 0;
        }
      }
      else {
        *(int *)(*(int *)(param_1 + 0xf8) + 0xc) = *(int *)(param_1 + 0xec);
        *(undefined4 *)(DAT_803deee8 + (*(uint *)(param_1 + 0xec) & 0xff) * 0x404 + 0xf0) =
             0xffffffff;
        *(undefined4 *)(DAT_803deee8 + (*(uint *)(param_1 + 0xec) & 0xff) * 0x404 + 0xfc) =
             *(undefined4 *)(param_1 + 0xfc);
        puVar1 = *(undefined4 **)(param_1 + 0xf8);
        if (puVar1 != *(undefined4 **)(param_1 + 0xfc)) {
          if ((undefined4 *)puVar1[1] == (undefined4 *)0x0) {
            DAT_803def74 = *puVar1;
          }
          else {
            *(undefined4 *)puVar1[1] = *puVar1;
          }
          iVar2 = **(int **)(param_1 + 0xf8);
          if (iVar2 != 0) {
            *(int *)(iVar2 + 4) = (*(int **)(param_1 + 0xf8))[1];
          }
          **(int **)(param_1 + 0xf8) = DAT_803def78;
          if (DAT_803def78 != 0) {
            *(undefined4 *)(DAT_803def78 + 4) = *(undefined4 *)(param_1 + 0xf8);
          }
          *(undefined4 *)(*(int *)(param_1 + 0xf8) + 4) = 0;
          DAT_803def78 = *(int *)(param_1 + 0xf8);
          *(undefined4 *)(param_1 + 0xf8) = 0;
        }
        *(undefined4 *)(param_1 + 0xf8) = 0;
        *(undefined4 *)(param_1 + 0xfc) = 0;
      }
    }
    else {
      *(undefined4 *)(DAT_803deee8 + (*(uint *)(param_1 + 0xf0) & 0xff) * 0x404 + 0xec) =
           *(undefined4 *)(param_1 + 0xec);
      if (*(uint *)(param_1 + 0xec) != 0xffffffff) {
        *(undefined4 *)(DAT_803deee8 + (*(uint *)(param_1 + 0xec) & 0xff) * 0x404 + 0xf0) =
             *(undefined4 *)(param_1 + 0xf0);
      }
      puVar1 = *(undefined4 **)(param_1 + 0xf8);
      if ((undefined4 *)puVar1[1] == (undefined4 *)0x0) {
        DAT_803def74 = *puVar1;
      }
      else {
        *(undefined4 *)puVar1[1] = *puVar1;
      }
      iVar2 = **(int **)(param_1 + 0xf8);
      if (iVar2 != 0) {
        *(int *)(iVar2 + 4) = (*(int **)(param_1 + 0xf8))[1];
      }
      **(int **)(param_1 + 0xf8) = DAT_803def78;
      if (DAT_803def78 != 0) {
        *(undefined4 *)(DAT_803def78 + 4) = *(undefined4 *)(param_1 + 0xf8);
      }
      *(undefined4 *)(*(int *)(param_1 + 0xf8) + 4) = 0;
      DAT_803def78 = *(int *)(param_1 + 0xf8);
      *(undefined4 *)(param_1 + 0xf8) = 0;
    }
  }
  return;
}

