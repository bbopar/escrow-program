  
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    program_pack::{IsInitialized, Pack},
    pubkey::Pubkey,
    sysvar::{rent::Rent, Sysvar},
    log::sol_log_compute_units,
};

use spl_token::state::Account as TokenAccount;

use crate::{error::EscrowError, instruction::EscrowInstruction, state::Escrow};

pub struct Processor;
impl Processor {
    pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
        let instruction = EscrowInstruction::unpack(instruction_data)?;

        match instruction {
            EscrowInstruction::InitEscrow { amount } => {
                msg!("Instruction: InitEscrow");
                Self::process_init_escrow(accounts, amount, program_id)
            },
            EscrowInstruction::Exchange { amount} => {
                msg!("Instruction: Exchange");
                Self::process_exchange(accounts, amount, program_id)
            },
            EscrowInstruction::Cancel {} => {
                msg!("Instruction: Cancel");
                Self::process_cancel_escrow(accounts, program_id)
            },
        }
    }

    fn process_init_escrow(
        accounts: &[AccountInfo],
        amount: u64,
        program_id: &Pubkey,
    ) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        // 1st acc (account initializer - person who wants to exchange tokens, msg sender - main account)
        let initializer = next_account_info(account_info_iter)?;

        if !initializer.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        // 2nd acc (this is temporary X account of person who wants to exchange tokens)
        let temp_token_account = next_account_info(account_info_iter)?;
        // 3rd acc (temporary X account created just for transfer of tokens to the escrow account)
        let token_to_receive_account = next_account_info(account_info_iter)?;

        // Nothing terrible would happen if we didn't add this check. Instead, Bob's
        // transaction would fail because the Token Program will attempt to send the Y tokens
        // to Alice but not be the owner of the token_to_receive_account. That said, it seems
        // more reasonable explicitly specify which transaction failed/led to the invalid state.
        // spl_token is a crate and it's aka the token program
        if *token_to_receive_account.owner != spl_token::id() {
            return Err(ProgramError::IncorrectProgramId);
        }

        // 4th account (escrow account to hold tokens for transfer)
        let escrow_account = next_account_info(account_info_iter)?;
        
        // Most times you want your accounts to be rent-exempt, because if
        // balances go to zero, they DISAPPEAR (i.e., purged from memory at runtime)!
        // This is why we're checking whether escrow (state) account is exempt. 
        // If we didn't do this check, and Alice were to pass in a non-rent-exempt account,
        // the account balance might go to zero balance before Bob takes the trade.
        // With the account gone, Alice would have no way to recover her tokens.
        let rent = &Rent::from_account_info(next_account_info(account_info_iter)?)?;

        if !rent.is_exempt(escrow_account.lamports(), escrow_account.data_len()) {
            return Err(EscrowError::NotRentExempt.into());
        }

        let mut escrow_info = Escrow::unpack_unchecked(&escrow_account.data.borrow())?;
        if escrow_info.is_initialized() {
            return Err(ProgramError::AccountAlreadyInitialized);
        }

        // populate the Escrow struct's fields
        escrow_info.is_initialized = true;
        escrow_info.initializer_pubkey = *initializer.key;
        escrow_info.temp_token_account_pubkey = *temp_token_account.key;
        escrow_info.initializer_token_to_receive_account_pubkey = *token_to_receive_account.key;
        escrow_info.expected_amount = amount;

        // Serialize our escrow_info object using 'pack' default function, which internally
        // calls our 'pack_into_slice' function.
        Escrow::pack(escrow_info, &mut escrow_account.data.borrow_mut())?; // `pack` is another default function which internally calls our pack_into_slice function.

        // Now, we need to transfer (user space) ownership of the temporary token account to the PDA...

		// What is a PDA (Program derived address)?
		//		0. https://docs.solana.com/developing/programming-model/calling-between-programs#program-derived-addresses
		//		1. Allows programmaticly generated signature to be used when calling between programs.
		//		2. To give a program the authority over an account and later transfer that authority to another.
		//		3. Allow programs to control specific addresses, called program addresses, in such a way that no external user can generate valid transactions with signatures for those addresses.
		//		4. Allow programs to programmatically sign for program addresses that are present in instructions invoked via Cross-Program Invocations.
		//		5. Given the previous two conditions, users can securely transfer or assign the authority of on-chain assets to program addresses and the program can then assign that authority elsewhere at its discretion.
		//		6. A Program address does not lie on the ed25519 curve and therefore has no valid private key associated with it, and thus generating a signature for it is impossible.
		//		7. While it has no private key of its own, it can be used by a program to issue an instruction that includes the Program address as a signer.

		// Create a PDA by passing in an array of seeds and the program_id to `find_program_address`.
		// Passing a static seed: "escrow".
		// We need 1 PDA that can own N temporary token accounts for different escrows occuring at any and possibly the same point in time.
		// We won't need the bump seed in Alice's tx.
        let (pda, _bump_seed) = Pubkey::find_program_address(&[b"escrow"], program_id);

        // To transfer the (user space) ownership of the temporary token account to the PDA,
		//		we will call the token program from our escrow program.
		//		This is called a Cross-Program Invocation (opens new window)
		//			and executed using either the invoke or the invoke_signed function.

		// Get the token_program account.
		// The program being called through a CPI (Cross-Program Invocation) must be included as an account in the 2nd argument of invoke
        let token_program = next_account_info(account_info_iter)?;

        // Now we create the instruction that the token program would expect were we executing a normal call.
		// `set_authority` is a builder helper function (in instruction.rs) to create such an instruction
		// Using [Signature Extension concept](https://docs.solana.com/developing/programming-model/calling-between-programs#instructions-that-require-privileges)
		//		because Alice signed the InitEscrow transaction, the program can make the token program set_authority CPI and include her pubkey as a signer pubkey.
		//		This is necessary because changing a token account's owner should of course require the approval of the current owner.
        let owner_change_ix = spl_token::instruction::set_authority(
            token_program.key,                                  // token program id
            temp_token_account.key,                                // account whose authority we'd like to change
            Some(&pda),                                     // account that's the new authority (in this case the PDA)
            spl_token::instruction::AuthorityType::AccountOwner,              // the type of authority change (change the owner)
            initializer.key,                                      // the current account owner (Alice -> initializer.key)
            &[&initializer.key],                                // the public keys signing the CPI
        )?;

        msg!("Calling the token program to transfer token account ownership...");
        invoke(
            &owner_change_ix,                                     // the instruction CPI (Cross-Program Instruction)
            &[                                                  // The accounts required by the CPI instruction
                temp_token_account.clone(),                                 // Account of the program we are calling
                initializer.clone(),                                        
                token_program.clone(),
            ],
        )?;

        Ok(())
    }

    fn process_exchange(
        accounts: &[AccountInfo],
        amount_expected_by_taker: u64,
        program_id: &Pubkey,
    ) -> ProgramResult {
        // This is Bob's Transaction. Alice has already created the Escrow,
        // so now Bob needs to send the correct amount of Y tokens to the Escrow,
        // then the Escrow will send him Alice's X tokens and Alice his Y tokens.
        // -------------------------------get all the accounts---------------------------------------------- //

        let account_info_iter = &mut accounts.iter();

        // 0. `[signer]` The account of the person taking the trade
        let taker_main_acc = next_account_info(account_info_iter)?;
        if !taker_main_acc.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        // 1. `[writable]` The taker's token account for the token they send (Y)
        let taker_y_acc = next_account_info(account_info_iter)?;

        // 2. `[writable]` The taker's token account for the token they will receive should the trade go through (X)
        let taker_x_acc = next_account_info(account_info_iter)?;

        // 3. `[writable]` The PDA's temp token account to get tokens from and eventually close
        let pda_temp_x_acc = next_account_info(account_info_iter)?;
        let pda_temp_x_info = TokenAccount::unpack(&pda_temp_x_acc.data.borrow())?;

        // 4. `[writable]` The initializer's main account to send their rent fees to
        let initializer_main_acc = next_account_info(account_info_iter)?;

        // 5. `[writable]` The initializer's token account that will receive tokens (Y)
        let initializer_y_acc = next_account_info(account_info_iter)?;

        // 6. `[writable]` The escrow account holding the escrow info
        let escrow_acc = next_account_info(account_info_iter)?;
        let escrow_info = Escrow::unpack(&escrow_acc.data.borrow())?;
        // check that the passed temp account matches what's saved in escrow state
        if escrow_info.temp_token_account_pubkey != *pda_temp_x_acc.key {
            return Err(ProgramError::InvalidAccountData);
        }
        // check that the passed initializer account matches what's saved in escrow state
        if escrow_info.initializer_pubkey != *initializer_main_acc.key {
            return Err(ProgramError::InvalidAccountData);
        }
        // check that the passed Y token account matches what's saved in escrow state
        if escrow_info.initializer_token_to_receive_account_pubkey != *initializer_y_acc.key {
            return Err(ProgramError::InvalidAccountData);
        }

        // 7. `[]` The token program
        let token_program_acc = next_account_info(account_info_iter)?;

        // 8. `[]` The PDA account
        let pda_acc = next_account_info(account_info_iter)?;

        // quant checks

        let (pda, bump_seed) = Pubkey::find_program_address(&[b"escrow"], program_id);

        if amount_expected_by_taker != pda_temp_x_info.amount {
            return Err(EscrowError::ExpectedAmountMismatch.into());
        }

        // instruction -> move Y tokens from bob to alice
        // To perform the actual transfer we use spl_token::instruction::transfer built-in
        // method, which is a CPI. We then will use invoke() to call this new instruction
        // and pass in this instruction along with the accounts involved.
        // This is using Signature Extension to make the token transfer to Alice's Y
        // token account on Bob's behalf.
        let transfer_to_initializer_ix = spl_token::instruction::transfer(
            token_program_acc.key,
            taker_y_acc.key,
            initializer_y_acc.key,
            taker_main_acc.key,
            &[&taker_main_acc.key],
            escrow_info.expected_amount,
        )?;

        msg!("Calling the token program to transfer tokens to the escrow's initializer...");

        // use signature extension to make the token transfer to Alice's Y token account on Bob's behalf.
        invoke(
            &transfer_to_initializer_ix,
            &[
                taker_y_acc.clone(),
                initializer_y_acc.clone(),
                taker_main_acc.clone(),
                token_program_acc.clone(),
            ],
        )?;

        // move X from alice to bob
        let transfer_to_taker_ix = spl_token::instruction::transfer(
            token_program_acc.key, //always first
            pda_temp_x_acc.key,
            taker_x_acc.key,
            &pda,
            &[&pda],
            pda_temp_x_info.amount,
        )?;

        msg!("Calling the token program to transfer tokens to the taker...");

        // note we're using invoke_signed here because we're signing with a pda
        // because the pda doesn't actually have a private key associatd with it (its off the curve)
        // we instead pass its seed, which is used as proof
        // no other program can fake this PDA because it requires 2 things: 1) the seed and 2) the program id of the parent
        // - the seed we pass now
        // - the program id is naturally coming from the escrow program
        invoke_signed(
            &transfer_to_taker_ix,
            &[
                //the order DOES NOT MATTER
                pda_temp_x_acc.clone(),
                taker_x_acc.clone(),
                pda_acc.clone(), //has to be passed into the instruction to prevent preimage attacks
                token_program_acc.clone(),
            ],
            &[&[&b"escrow"[..], &[bump_seed]]],
        )?;

        // ----------------------------------------------------------------------------- clean up

        // rm [3 ]temp X acc
        // rm [6] escrow acc

        // we close the account by transferring its "rent-exempt" balance out of it
        let close_pdas_temp_acc_ix = spl_token::instruction::close_account(
            token_program_acc.key,
            pda_temp_x_acc.key,       //from temp account
            initializer_main_acc.key, //to initializer main account
            &pda,
            &[&pda],
        )?;

        msg!("Calling the token program to close pda's temp account...");

        // same story as above - since we're moving out of a PDA account, we use invoke_signed
        invoke_signed(
            &close_pdas_temp_acc_ix,
            &[
                pda_temp_x_acc.clone(),
                initializer_main_acc.clone(),
                pda_acc.clone(),
                token_program_acc.clone(),
            ],
            &[&[&b"escrow"[..], &[bump_seed]]],
        )?;

        msg!("Closing the escrow account...");

        **initializer_main_acc.lamports.borrow_mut() = initializer_main_acc
            .lamports()
            .checked_add(escrow_acc.lamports())
            .ok_or(EscrowError::AmountOverflow)?; //add the balance to initializer's acc

        **escrow_acc.lamports.borrow_mut() = 0; //empty the balance
        *escrow_acc.data.borrow_mut() = &mut []; //AND zero out its data

        Ok(())
    }

    fn process_cancel_escrow(
        accounts: &[AccountInfo],
        program_id: &Pubkey,
    ) -> ProgramResult {
        // ------------------------------------GET ACCOUNTS----------------------------------------- //
        let accounts_info_iter = &mut accounts.iter();

        // 1st acc -> Escrow initializer account
        let initializer_main_acc = next_account_info(accounts_info_iter)?;
        // 2nd acc -> Token program 
        let token_program_acc = next_account_info(accounts_info_iter)?;
        // 3rd acc -> Temp X account
        let temp_x_acc = next_account_info(accounts_info_iter)?;
        // 4th acc -> Escrow initializer X account
        let initializer_x_acc = next_account_info(accounts_info_iter)?;
        // 5th acc -> The Escrow account
        let escrow_acc = next_account_info(accounts_info_iter)?;
        // 6th acc -> The PDA account
        let pda_acc = next_account_info(accounts_info_iter)?;

        // -------------------------------------checks-------------------------------------------- //
        // deserialize the escrow account
        let escrow_info = Escrow::unpack(&escrow_acc.data.borrow())?;

        // check that the sender is indeed the initializer who created the escrow
        if escrow_info.initializer_pubkey != *initializer_main_acc.key {
            return Err(ProgramError::InvalidAccountData);
        }

        // check that initializer is listed as signer
        if !initializer_main_acc.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }

        // check that temp_x_acc is what we're expecting
        if escrow_info.temp_token_account_pubkey != *temp_x_acc.key {
            return Err(ProgramError::InvalidAccountData);
        }

        // -------------------------------THE PDA account------------------------------------------- //

        // APPROACH 1: FROM TUTORIAL - works
        let (pda, bump_seed) = Pubkey::find_program_address(&[b"escrow"], program_id);
        // Program log: pda and seed are: 2CVTH6qZCuYWyCPigStv7rTPfaCW9FTmFtzTfq3u8LBU, 254
        msg!("pda and seed: {}, {}", pda, bump_seed);

        // -------------------------------send x token back----------------------------------------- //

        // similarly to our Escrow, pack/unpack turns a slice into an actual account info
        let temp_x_info = TokenAccount::unpack(&temp_x_acc.data.borrow())?;

        let transfer_x_tokens_back_ix = spl_token::instruction::transfer(
            token_program_acc.key,
            temp_x_acc.key,
            initializer_x_acc.key,
            &pda,
            &[&pda],
            temp_x_info.amount, //get the amount in x tokens programmatically
        )?;

        //invoke here because we're asking the token program to do something for us
        invoke_signed(
            &transfer_x_tokens_back_ix,
            &[
                temp_x_acc.clone(),
                initializer_x_acc.clone(),
                pda_acc.clone(),
                token_program_acc.clone(),
            ],
            &[&[&b"escrow"[..], &[bump_seed]]],
        )?;

        // ----------------------------------------------------------------------------- clean up

        sol_log_compute_units();

        //1) close the temp acc by transferring rent out of it
        let close_temp_x_acc_ix = spl_token::instruction::close_account(
            token_program_acc.key,
            temp_x_acc.key,
            initializer_x_acc.key,
            &pda,
            &[&pda],
        )?;

        invoke_signed(
            &close_temp_x_acc_ix,
            &[
                temp_x_acc.clone(),
                initializer_x_acc.clone(),
                pda_acc.clone(),
                token_program_acc.clone(),
            ],
            &[&[&b"escrow"[..], &[bump_seed]]],
        )?;

        //2) close the escrow acc by transferring rent out of it AND zeroing out the data
        **initializer_main_acc.lamports.borrow_mut() = initializer_main_acc
            .lamports()
            .checked_add(escrow_acc.lamports())
            .ok_or(EscrowError::AmountOverflow)?;
        **escrow_acc.lamports.borrow_mut() = 0;
        *escrow_acc.data.borrow_mut() = &mut [];

        sol_log_compute_units();

        Ok(())
    }
}