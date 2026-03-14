module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  moduleNameMapper: {
    '^isomorphic-registry$': '<rootDir>/../isomorphic-registry/src/index',
    '^raft-consensus$': '<rootDir>/../raft-consensus/src/index'
  }
};
