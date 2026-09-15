const GQL_ENDPOINT = "https://api.example.com/graphql";

const GET_USER_QUERY = `
  query GetUserProfile($userId: ID!, $includeHistory: Boolean) {
    user(id: $userId) {
      id
      name
      email
      role
    }
  }
`;

const UPDATE_SETTINGS_MUTATION = `
  mutation UpdateUserSettings($input: SettingsInput!) {
    updateSettings(input: $input) {
      success
    }
  }
`;

function executeQuery(query, variables) {
  return fetch(GQL_ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer token123"
    },
    body: JSON.stringify({ query, variables })
  });
}
