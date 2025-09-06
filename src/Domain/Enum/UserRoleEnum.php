<?php

declare(strict_types=1);

namespace App\Domain\Enum;

enum UserRoleEnum: string
{
    case USER = 'ROLE_USER';
    case ADMIN_CMS = 'ROLE_ADMIN_CMS';
}
