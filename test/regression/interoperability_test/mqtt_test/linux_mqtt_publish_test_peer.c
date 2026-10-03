/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

#include "mqtt_interoperability_test.h"

/* The NetX client publishes to the broker and subscribes to what it
   publishes, so this instance has nothing to send.  */
INT mqtt_publisher_entry(TLS_TEST_INSTANCE* instance_ptr)
{
    (void)instance_ptr;
    return 0;
}
