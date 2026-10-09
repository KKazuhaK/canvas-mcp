import { Component, type ErrorInfo, type ReactNode } from 'react'
import Alert from '@mui/material/Alert'
import AlertTitle from '@mui/material/AlertTitle'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import { Translation } from 'react-i18next'

interface State {
  crashed: boolean
}

/**
 * Last line of defence for a render crash. It shows a fixed, localized message:
 * never the error text, never a stack trace, and nothing is logged with request
 * or form data.
 */
export default class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { crashed: false }

  static getDerivedStateFromError(): State {
    return { crashed: true }
  }

  componentDidCatch(_error: Error, _info: ErrorInfo): void {
    // Deliberately empty: nothing from the failed render is reported or kept.
  }

  render() {
    if (!this.state.crashed) return this.props.children
    return (
      <Translation>
        {(t) => (
          <Box sx={{ p: 2, maxWidth: 560, mx: 'auto', mt: 6 }}>
            <Alert
              severity="error"
              role="alert"
              action={
                <Button color="inherit" size="small" onClick={() => window.location.reload()}>
                  {t('common:states.reload')}
                </Button>
              }
            >
              <AlertTitle>{t('common:states.crash.title')}</AlertTitle>
              {t('common:states.crash.body')}
            </Alert>
          </Box>
        )}
      </Translation>
    )
  }
}
