import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty } from 'class-validator';

export class RefreshTokenDto {
  @ApiProperty({ example: 'u2werrdjf-trtyygghhjmmmmm-ftgt' })
  @IsNotEmpty()
  @IsString()
  refreshToken: string;
}
