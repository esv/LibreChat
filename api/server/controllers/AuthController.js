const cookies = require('cookie');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const {
  registerUser,
  resetPassword,
  setAuthTokens,
  requestPasswordReset,
} = require('~/server/services/AuthService');
const { findSession, getUserById, deleteAllUserSessions } = require('~/models');
const { findUser, createUser, updateUser } = require('~/models/userMethods');
const { logger } = require('~/config');

const registrationController = async (req, res) => {
  try {
    const response = await registerUser(req.body);
    const { status, message } = response;
    res.status(status).send({ message });
  } catch (err) {
    logger.error('[registrationController]', err);
    return res.status(500).json({ message: err.message });
  }
};

const resetPasswordRequestController = async (req, res) => {
  try {
    const resetService = await requestPasswordReset(req);
    if (resetService instanceof Error) {
      return res.status(400).json(resetService);
    } else {
      return res.status(200).json(resetService);
    }
  } catch (e) {
    logger.error('[resetPasswordRequestController]', e);
    return res.status(400).json({ message: e.message });
  }
};

const resetPasswordController = async (req, res) => {
  try {
    const resetPasswordService = await resetPassword(
      req.body.userId,
      req.body.token,
      req.body.password,
    );
    if (resetPasswordService instanceof Error) {
      return res.status(400).json(resetPasswordService);
    } else {
      await deleteAllUserSessions({ userId: req.body.userId });
      return res.status(200).json(resetPasswordService);
    }
  } catch (e) {
    logger.error('[resetPasswordController]', e);
    return res.status(400).json({ message: e.message });
  }
};

/**
 * Authenticates a user with YT cookies when JWT auth is not available
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Promise<Object>} - Response object or null if authentication fails
 */
const authenticateWithYt = async (req, res) => {
  // Using environment variables for configuration
  const YT_CLUSTER_BASE_PATH = process.env.YT_CLUSTER_BASE_PATH;
  const YT_CLUSTER_NAME = process.env.YT_CLUSTER_NAME;

  const rawCookies = req.headers.cookie;

  if (!rawCookies) {
    return null;
  }

  try {
    // First request to get login info
    const clusterResponse = await axios.get(
      `${YT_CLUSTER_BASE_PATH}/api/cluster-info/${YT_CLUSTER_NAME}`,
      {
        headers: {
          Cookie: rawCookies,
        },
        withCredentials: true,
        httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }),
      },
    );

    // Extract login from response
    const login = clusterResponse.data?.token?.login;
    const csrfToken = clusterResponse.data?.token?.csrf_token;
    if (!login || !csrfToken) {
      return null;
    }

    // Second request to get user details
    const userResponse = await axios.post(
      `${YT_CLUSTER_BASE_PATH}/api/yt/${YT_CLUSTER_NAME}/api/v4/get`,
      {
        path: `//sys/users/${login}/@azure`,
        suppress_access_tracking: 'true',
      },
      {
        headers: {
          Cookie: rawCookies,
          'x-csrf-token': csrfToken,
          'x-custom-request-id': 'usersData',
          'Content-Type': 'application/json',
        },
        withCredentials: true,
        httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }),
      },
    );

    // Extract user info
    const displayName = userResponse.data?.value?.display_name || '';
    const email = userResponse.data?.value?.email;

    if (!email) {
      return null;
    }

    // Find or create user
    let user = await findUser({ email });

    if (user) {
      // Update name if needed
      if (displayName && user.name !== displayName) {
        user.name = displayName;
        user = await updateUser(user._id, user);
      }
    } else {
      // Create new user
      const username = email.split('@')[0];
      user = await createUser(
        {
          provider: YT_CLUSTER_NAME,
          username,
          email,
          emailVerified: true,
          name: displayName,
        },
        true,
        true,
      );
    }

    // Set auth tokens and return
    if (user) {
      const token = await setAuthTokens(user._id, res);
      return { token, user };
    }

    return null;
  } catch (error) {
    logger.error(`YT authentication error: ${error.message}`);
    return null;
  }
};

const refreshController = async (req, res) => {
  const refreshToken = req.headers.cookie ? cookies.parse(req.headers.cookie).refreshToken : null;

  // If no refresh token is provided, try Planck auth immediately
  if (!refreshToken) {
    const authResult = await authenticateWithYt(req, res);

    if (authResult) {
      return res.status(200).send(authResult);
    }

    return res.status(200).send('Refresh token not provided');
  }

  try {
    const payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await getUserById(payload.id, '-password -__v -totpSecret');

    if (!user) {
      // User not found - try Planck auth
      const authResult = await authenticateWithYt(req, res);
      if (authResult) {
        return res.status(200).send(authResult);
      }
      return res.status(401).redirect('/login');
    }

    const userId = payload.id;

    if (process.env.NODE_ENV === 'CI') {
      const token = await setAuthTokens(userId, res);
      return res.status(200).send({ token, user });
    }

    // Find the session with the hashed refresh token
    const session = await findSession({ userId: userId, refreshToken: refreshToken });

    if (session && session.expiration > new Date()) {
      const token = await setAuthTokens(userId, res, session._id);
      res.status(200).send({ token, user });
    } else if (req?.query?.retry) {
      // Retrying from a refresh token request that failed (401)
      const authResult = await authenticateWithYt(req, res);
      if (authResult) {
        return res.status(200).send(authResult);
      }
      res.status(403).send('No session found');
    } else if (payload.exp < Date.now() / 1000) {
      const authResult = await authenticateWithYt(req, res);
      if (authResult) {
        return res.status(200).send(authResult);
      }
      res.status(403).redirect('/login');
    } else {
      const authResult = await authenticateWithYt(req, res);
      if (authResult) {
        return res.status(200).send(authResult);
      }
      res.status(401).send('Refresh token expired or not found for this user');
    }
  } catch (err) {
    logger.error(`[refreshController] Refresh token: ${refreshToken}`, err);
    const authResult = await authenticateWithYt(req, res);
    if (authResult) {
      return res.status(200).send(authResult);
    }
    res.status(403).send('Invalid refresh token');
  }
};

module.exports = {
  refreshController,
  registrationController,
  resetPasswordController,
  resetPasswordRequestController,
};
