#ifndef USER_STORE_H_ 
#define USER_STORE_H_

#include <stdio.h>
#include <stdint.h>
#include "messaging_bp.h"


typedef struct user_entry
{
    uint8_t info[32];
    uint8_t wrapped_password[32];
    uint8_t password_length;
    bool isOccupied;
} user_entry_t;


/**
 * @brief Adds a new entry to the user store.
 *
 * This function adds a new entry to the user store and returns the index of the new entry.
 * 
 * @param[in] new_entry Pointer to the new entry to be added.
 * @param[out] index Pointer to the variable where the index of the new entry will be stored.
 * 
 * @return true if the entry was added successfully, false otherwise.
 */
bool user_store_add_new_entry(struct AddEntry* new_entry, uint8_t* index);

/**
 * @brief Deletes a user entry from the store.
 *
 * This function removes the user entry at the specified index from the user store.
 *
 * @param index The index of the user entry to be deleted.
 * @return true if the entry was successfully deleted, false otherwise.
 */
bool user_store_del_entry(uint8_t index);


/**
 * @brief Modifies the password for a user in the user store.
 *
 * This function updates the password for a specified user in the user store.
 *
 * @param modify A pointer to a Modify structure containing the necessary
 *               information to modify the user's password.
 * @return true if the password was successfully modified, false otherwise.
 */
bool user_store_modify_password(struct Modify* modify);

/**
 * @brief Reads a user entry from the user store.
 *
 * This function reads a user entry from the user store based on the provided
 * read_entry structure and fills the read_entry_rsp structure with the
 * corresponding response data.
 *
 * @param read_entry Pointer to a ReadEntry structure containing the details
 *                   of the entry to be read.
 * @param read_entry_rsp Pointer to a ReadEntryRsp structure where the response
 *                       data will be stored.
 * @return true if the entry was successfully read, false otherwise.
 */
bool user_store_read_entry(struct ReadEntry* read_entry, struct ReadEntryRsp* read_entry_rsp);

#endif