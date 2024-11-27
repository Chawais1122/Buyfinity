export const AUTH_CONSTANTS = {
  PASSWORD_REGEX_PATTERN:
    /^(?=[A-Za-z0-9@#$%^&*()+!={}~`_\[\]\'\\/:;,.<>?~"|\-\[\]]+$)(?=.*[a-z])(?=.*[0-9])(?=.*[@#$%^&*()+!={}~`_\[\]\'\\/:;,.<>?~"|\-\[\]]).{8,}$/,
};

export enum AllowedRoles {
  BUYER = 'BUYER',
  SELLER = 'SELLER',
}
