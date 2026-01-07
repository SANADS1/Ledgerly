import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import type { Request } from 'express';
import { AuthMeta } from './types/types/auth-meta.type';


@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Post('register')
    @ApiOperation({ summary: 'Register a new user' })
    @ApiResponse({ status: 201, description: 'User registered successfully' })
    register(
        @Body() dto: RegisterDto,
        @Req() req: Request,
    ) {
        return this.authService.register(dto, {
        ip: req.ip ?? req.socket?.remoteAddress,
        userAgent: req.headers['user-agent'],
        });
    }

    @Post('login')
    login(
        @Body() dto: LoginDto,
        @Req() req: Request,
    ) {
        return this.authService.login(dto, {
        ip: req.ip ?? req.socket?.remoteAddress,
        userAgent: req.headers['user-agent'],
        });
    }

    @Post('refresh')
    @ApiOperation({ summary: 'Refresh login token' })
    @ApiResponse({ status: 201, description: 'Token refresh successfully' })
    async refresh(
    @Body() dto: RefreshTokenDto,
    @Req() req: Request,
    ) {
    const meta: AuthMeta = {
        ip: req.ip ?? 'unknown',
        userAgent: req.headers['user-agent'] ?? 'unknown',
    };

    return this.authService.refresh(dto.refreshToken, meta);
    }


    @ApiBearerAuth('access-token')
    @UseGuards(JwtAuthGuard)
    @Get('me')
    getProfile(@Req() req) {
        return req.user;
    }

    @Post('logout')
    async logout(@Body() dto: RefreshTokenDto) {
    return this.authService.logout(dto.refreshToken);
    }

    @Post('logout-all')
    @UseGuards(JwtAuthGuard)
    async logoutAll(@Req() req) {
    return this.authService.logoutAll(req.user.sub);
    }

}
