// Function: FUN_80009a94
// Entry: 80009a94
// Size: 128 bytes

void FUN_80009a94(uint param_1)

{
  if ((param_1 & 4) != 0) {
    FUN_8000b624();
  }
  if ((param_1 & 1) != 0) {
    FUN_8000a380(1,1,0);
  }
  if ((param_1 & 2) != 0) {
    FUN_8000a380(2,1,0);
  }
  if ((param_1 & 8) != 0) {
    FUN_8000d01c();
  }
  return;
}

