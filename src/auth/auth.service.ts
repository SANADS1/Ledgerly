import { Injectable, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import { PasswordService } from '../common/security/password.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import * as crypto from 'crypto';
import { AuthMeta } from './types/types/auth-meta.type';

@Injectable()
export class AuthService {
  constructor(
    private jwt: JwtService,
    private prisma: PrismaService,
  ) { }

  async register(dto: RegisterDto, meta: AuthMeta) {
    const passwordHash = await PasswordService.hash(dto.password);

    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        passwordHash,
      },
    });

    return this.issueTokens(user.id, user.role, meta);
  }

  async login(dto: LoginDto, meta: AuthMeta) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // 🔐 ACCOUNT LOCK CHECK (NEW)
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      throw new UnauthorizedException('Account temporarily locked');
    }

    //YOUR SNIPPET STARTS HERE
    const isValid = await PasswordService.verify(
      dto.password,
      user.passwordHash,
    );

    if (!isValid) {
      const attempts = user.failedAttempts + 1;

      await this.prisma.user.update({
        where: { id: user.id },
        data: {
          failedAttempts: attempts,
          lockedUntil:
            attempts >= 5
              ? new Date(Date.now() + 15 * 60 * 1000)
              : null,
        },
      });

      throw new UnauthorizedException('Invalid credentials');
    }

    //RESET FAILED ATTEMPTS ON SUCCESS (NEW)
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        failedAttempts: 0,
        lockedUntil: null,
      },
    });

    return this.issueTokens(user.id, user.role, meta);
  }


  async refresh(refreshToken: string, meta: AuthMeta) {
    if (!refreshToken) {
    throw new UnauthorizedException('Refresh token missing');
    }
    
    const tokenHash = crypto
      .createHash('sha256')
      .update(refreshToken)
      .digest('hex');

    const storedToken = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
      include: { user: true },
    });

    // ❌ Token does not exist → reuse or fake
    if (!storedToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // ❌ Token already revoked → replay attack
    if (storedToken.revokedAt) {
      // 🔥 SECURITY RESPONSE: revoke all sessions
      await this.prisma.refreshToken.updateMany({
        where: { userId: storedToken.userId },
        data: { revokedAt: new Date() },
      });

      throw new UnauthorizedException('Refresh token reuse detected');
    }

    // ❌ Token expired
    if (storedToken.expiresAt < new Date()) {
      throw new UnauthorizedException('Refresh token expired');
    }

    // ✅ Revoke current token (single-use)
    await this.prisma.refreshToken.update({
      where: { id: storedToken.id },
      data: { revokedAt: new Date() },
    });

    // ✅ Issue new token pair (rotation)
    return this.issueTokens(
      storedToken.userId,
      storedToken.user.role,
      meta,
    );
  }


  async logout(refreshToken: string) {
    const tokenHash = crypto
      .createHash('sha256')
      .update(refreshToken)
      .digest('hex');

    await this.prisma.refreshToken.updateMany({
      where: {
        tokenHash,
        revoked: false,
      },
      data: {
        revoked: true,
      },
    });

    return { message: 'Logged out successfully' };
  }

  async logoutAll(userId: string) {
    await this.prisma.refreshToken.updateMany({
      where: {
        userId,
        revoked: false,
      },
      data: {
        revoked: true,
      },
    });

    return { message: 'Logged out from all devices' };
  }

  private async issueTokens(userId: string, role: string, meta: AuthMeta) {
    const accessToken = this.jwt.sign({ sub: userId, role });

    const refreshToken = crypto.randomBytes(64).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

    await this.prisma.refreshToken.create({
      data: {
        tokenHash,
        userId,
        ipAddress: meta.ip,
        userAgent: meta.userAgent,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });

    return {
      accessToken,
      refreshToken,
    };
  }
}
