/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "aes-independant.h"
#include "hal.h"
#include "poly_masked_sbox.h"
#include "random_bytes.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>
#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t sbox_call(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *sharing) {
#else
uint8_t sbox_call(uint8_t *sharing, uint8_t len) {
#endif

  if (NUM_SHARES > 16) {
    return 0x00;
  }
  share secret_sharing[NUM_SHARES] = {0};
  for (int i = 0; i < NUM_SHARES; i++) {
    secret_sharing[i] = sharing[i];
  }
#ifndef DISABLE_RANDOMNESS
  init_aes_rand();
#else
  reset_ctr();
#endif
  // inplace sbox computation on the sharing
  masked_sbox(secret_sharing);

  // write back result
  uint8_t response[16] = {0};
  for (int i = 0; i < NUM_SHARES; i++) {
    response[i] = (uint8_t)secret_sharing[i];
  }

  simpleserial_put('r', 16, response);

  return 0x00;
}

#if SS_VER == SS_VER_2_1 || SS_VER == SS_VER_2_0
uint8_t echo_test(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *data) {
#else
uint8_t echo_test(uint8_t *data, uint8_t len) {
#endif
  simpleserial_put('r', 16, data);
  return 0x00;
}

int main(void) {

  platform_init();
  init_uart();
  trigger_setup();

  simpleserial_init();
  aes_indep_init();
  uint8_t aes_seed[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                          0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  aes_indep_key(aes_seed);
// simpleserial 2.1 maps the 'p' command to 0x01, all other commands should work
// as expected
#if SS_VER == SS_VER_2_1
  simpleserial_addcmd(0x01, 16, sbox_call);
#else
  simpleserial_addcmd('p', 16, sbox_call);
#endif
  simpleserial_addcmd('e', 16, echo_test);
  while (1)
    simpleserial_get();
}
