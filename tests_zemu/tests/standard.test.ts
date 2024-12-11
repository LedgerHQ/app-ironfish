/** ******************************************************************************
 *  (c) 2018 - 2024 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

import Zemu, { ButtonKind, isTouchDevice, zondaxMainmenuNavigation } from '@zondax/zemu'
import { PATH, defaultOptions, expectedKeys, models, tx_output_2_known, tx_output_3 } from './common'
import IronfishApp, {
  IronfishKeys,
  KeyResponse,
  ResponseAddress,
  ResponseProofGenKey,
  ResponseSign,
  ResponseViewKey,
} from '@zondax/ledger-ironfish'

jest.setTimeout(500000)

describe('Standard', function () {
  test.concurrent.each(models)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('main menu', async function (m) {
    const sim = new Zemu(m.path)
    try {
      const mainmenuNavigation = zondaxMainmenuNavigation(m.name)
      await sim.start({ ...defaultOptions, model: m.name })
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, mainmenuNavigation.schedule)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get app version', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new IronfishApp(sim.getTransport(), false)
      const resp = await app.getVersion()

      console.log(resp)

      expect(resp).toHaveProperty('testMode')
      expect(resp).toHaveProperty('major')
      expect(resp).toHaveProperty('minor')
      expect(resp).toHaveProperty('patch')
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new IronfishApp(sim.getTransport(), false)

      const resp: ResponseAddress = (await app.retrieveKeys(PATH, IronfishKeys.PublicAddress, false)) as ResponseAddress
      console.log(resp)

      expect(resp.publicAddress.toString('hex')).toEqual(expectedKeys.publicAddress)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('show address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: isTouchDevice(m.name) ? 'Confirm' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new IronfishApp(sim.getTransport(), false)

      const respRequest = app.retrieveKeys(PATH, IronfishKeys.PublicAddress, true)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_address`)

      const resp: ResponseAddress = (await respRequest) as ResponseAddress
      console.log(resp)
      expect(resp.publicAddress.toString('hex')).toEqual(expectedKeys.publicAddress)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get proof generation key', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new IronfishApp(sim.getTransport(), false)

      const resp: ResponseProofGenKey = (await app.retrieveKeys(PATH, IronfishKeys.ProofGenerationKey, false)) as ResponseProofGenKey
      console.log(resp)

      expect(resp.ak?.toString('hex')).toEqual(expectedKeys.ak)
      expect(resp.nsk?.toString('hex')).toEqual(expectedKeys.nsk)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('show view key', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: isTouchDevice(m.name) ? 'Approve' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new IronfishApp(sim.getTransport(), false)

      const respRequest = app.retrieveKeys(PATH, IronfishKeys.ViewKey, true)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_viewkey`)

      const resp: ResponseViewKey = (await respRequest) as ResponseViewKey
      console.log(resp)

      expect(resp.viewKey?.toString('hex')).toEqual(expectedKeys.viewKey)
      expect(resp.ivk?.toString('hex')).toEqual(expectedKeys.ivk)
      expect(resp.ovk?.toString('hex')).toEqual(expectedKeys.ovk)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign transaction with unknown asset ', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new IronfishApp(sim.getTransport(), false)

      await sim.toggleExpertMode()

      const txBlob = Buffer.from(tx_output_3, 'hex')
      const responsePublicAddress = await app.retrieveKeys(PATH, IronfishKeys.PublicAddress, false)
      console.log(responsePublicAddress)

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(PATH, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 200000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_3_out_tx_unknown`)

      const signatureResponse = (await signatureRequest) as ResponseSign
      console.log(signatureResponse)

      console.log(signatureResponse.signature.length)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign transaction with known assets show all outputs', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new IronfishApp(sim.getTransport(), false)

      await sim.toggleExpertMode()

      const txBlob = Buffer.from(tx_output_2_known, 'hex')
      const responsePublicAddress = await app.retrieveKeys(PATH, IronfishKeys.PublicAddress, false)
      console.log(responsePublicAddress)

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(PATH, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 200000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_2_out_tx_known`)

      const signatureResponse = (await signatureRequest) as ResponseSign
      console.log(signatureResponse)

      console.log(signatureResponse.signature.length)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('sign transaction with known assets hide change output', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new IronfishApp(sim.getTransport(), false)

      const txBlob = Buffer.from(tx_output_2_known, 'hex')
      const responsePublicAddress = await app.retrieveKeys(PATH, IronfishKeys.PublicAddress, false)
      console.log(responsePublicAddress)

      // do not wait here.. we need to navigate
      const signatureRequest = app.sign(PATH, txBlob)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 200000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_2_out_tx_known_hide_change`)

      const signatureResponse = (await signatureRequest) as ResponseSign
      console.log(signatureResponse)

      console.log(signatureResponse.signature.length)
    } finally {
      await sim.close()
    }
  })
})
